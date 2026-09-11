use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;

use anyhow::{bail, Result};
use indicatif::ProgressBar;

use super::entry::IndexEntry;
use crate::HashAlgorithm;

impl super::IndexFile {
    /// Create a new index file from a wordlist and hash algorithm.
    ///
    /// Hashes every line in the wordlist, writing 14-byte entries
    /// (8-byte hash prefix + 6-byte LE wordlist position) to the output file.
    /// The resulting index is unsorted — call [`sort`](Self::sort) next.
    pub fn build(
        algorithm: &dyn HashAlgorithm,
        wordlist_path: &Path,
        output_path: &Path,
        progress: Option<&ProgressBar>,
    ) -> Result<Self> {
        IndexBuilder::build(algorithm, wordlist_path, output_path, progress)?;
        Ok(super::IndexFile {
            path: output_path.to_path_buf(),
        })
    }
}

pub(crate) struct IndexBuilder;

impl IndexBuilder {
    /// Create an unsorted index from a wordlist and hash algorithm.
    ///
    /// The wordlist is treated as raw bytes delimited by `\n` (0x0A).
    /// Words may contain arbitrary byte sequences — no UTF-8 assumption.
    ///
    /// For each line in the wordlist:
    /// 1. Record the byte position *before* reading the line
    /// 2. Strip trailing `\n` and `\r` bytes from the line
    /// 3. Hash the trimmed word
    /// 4. Write a 14-byte index entry (8-byte hash prefix + 6-byte LE position)
    ///
    /// Returns the number of entries written.
    pub fn build(
        algorithm: &dyn HashAlgorithm,
        wordlist_path: &Path,
        output_path: &Path,
        progress: Option<&ProgressBar>,
    ) -> Result<u64> {
        let wordlist = std::fs::File::open(wordlist_path)?;
        let file_len = wordlist.metadata()?.len();
        let mut reader = BufReader::new(wordlist);

        // `File::create` truncates, and `BufReader::new` has not issued a single read yet,
        // so if these two paths name the same file the wordlist is destroyed before it is
        // read and the build then "succeeds" with zero entries. Refuse first.
        if is_same_file(wordlist_path, output_path) {
            bail!(
                "refusing to build: the output and the wordlist are the same file ({}). \
                 Building would truncate the wordlist before reading it.",
                output_path.display()
            );
        }

        let output = std::fs::File::create(output_path)?;
        let mut writer = BufWriter::new(output);

        if let Some(pb) = progress {
            pb.set_length(file_len);
        }

        // Hashing is the expensive, embarrassingly parallel part; reading the file is
        // inherently sequential. So this thread parses a batch of lines into
        // (position, word) pairs, worker threads hash the batch across all cores, and
        // the surviving entries are written back in wordlist order. The reader makes a
        // single forward pass and the output is byte-identical to a serial build.
        let threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);

        let mut entries_written: u64 = 0;
        let mut position: u64 = 0;

        // Reused across batches so the per-batch work does not reallocate.
        let mut line_buf = Vec::new();
        let mut batch = Batch::default();
        let mut entries: Vec<IndexEntry> = Vec::new();

        loop {
            batch.clear();

            // Parse one batch of trimmed words, remembering each word's line position.
            // `position` advances by the untrimmed line length for every line, so words
            // the algorithm later rejects still move it -- exactly as the serial path did.
            while batch.words.len() < BATCH_MAX_WORDS && batch.bytes.len() < BATCH_MAX_BYTES {
                line_buf.clear();
                let bytes_read = reader.read_until(b'\n', &mut line_buf)?;
                if bytes_read == 0 {
                    break;
                }

                // Both ends, matching PHP's trim($word, "\n\r") -- see the helper.
                let word = super::trim_record_separators(&line_buf);
                let start = batch.bytes.len();
                batch.bytes.extend_from_slice(word);
                batch.words.push(Word {
                    position,
                    start,
                    len: word.len(),
                });
                position += bytes_read as u64;
            }

            if batch.words.is_empty() {
                break;
            }

            // Hash the batch in parallel; `prefixes[i]` is `None` for a rejected word.
            let prefixes = hash_batch(algorithm, &batch, threads);

            entries.clear();
            for (word, prefix) in batch.words.iter().zip(&prefixes) {
                if let Some(prefix) = prefix {
                    entries.push(IndexEntry::new(*prefix, word.position));
                }
            }
            IndexEntry::write_bulk(&mut writer, &entries, entries.len())?;
            entries_written += entries.len() as u64;

            if let Some(pb) = progress {
                pb.set_position(position);
            }
        }

        writer.flush()?;

        check_wordlist_was_fully_read(position, file_len, wordlist_path)?;

        Ok(entries_written)
    }
}

/// One trimmed word inside a [`Batch`]: its slice within the batch byte buffer and
/// the wordlist position the entry must record.
struct Word {
    position: u64,
    start: usize,
    len: usize,
}

/// A batch of trimmed words handed to the workers: the concatenated word bytes and
/// the per-word ranges into them. Reused across batches to avoid reallocating.
#[derive(Default)]
struct Batch {
    bytes: Vec<u8>,
    words: Vec<Word>,
}

impl Batch {
    fn clear(&mut self) {
        self.bytes.clear();
        self.words.clear();
    }
}

/// A batch ends at whichever cap is reached first: a word count, or a byte size so a
/// run of very long words cannot make one batch consume unbounded memory.
const BATCH_MAX_WORDS: usize = 1 << 16;
const BATCH_MAX_BYTES: usize = 8 << 20;

/// Hash every word in `batch` across up to `threads` workers, returning each word's
/// stored 8-byte prefix (`None` where the algorithm rejected the word).
///
/// The output order matches `batch.words`, so the caller writes entries in wordlist
/// order and the index is byte-identical to a serial build. `HashAlgorithm` is
/// `Send + Sync`, so the one `&dyn` reference is shared across the workers as-is.
fn hash_batch(
    algorithm: &dyn HashAlgorithm,
    batch: &Batch,
    threads: usize,
) -> Vec<Option<[u8; 8]>> {
    let n = batch.words.len();
    let mut prefixes: Vec<Option<[u8; 8]>> = vec![None; n];

    let workers = threads.clamp(1, n.max(1));
    if workers <= 1 {
        for (word, slot) in batch.words.iter().zip(prefixes.iter_mut()) {
            *slot = hash_prefix(algorithm, &batch.bytes[word.start..word.start + word.len]);
        }
        return prefixes;
    }

    // Hand each worker a disjoint, contiguous slice of the output and the matching
    // range of words. `split_at_mut` keeps the borrows non-overlapping.
    let chunk = n.div_ceil(workers);
    std::thread::scope(|scope| {
        let bytes = &batch.bytes;
        let words = &batch.words;
        let mut base = 0usize;
        let mut rest = prefixes.as_mut_slice();
        while !rest.is_empty() {
            let take = chunk.min(rest.len());
            let (head, tail) = rest.split_at_mut(take);
            rest = tail;
            let start_idx = base;
            base += take;
            scope.spawn(move || {
                for (offset, slot) in head.iter_mut().enumerate() {
                    let word = &words[start_idx + offset];
                    *slot = hash_prefix(algorithm, &bytes[word.start..word.start + word.len]);
                }
            });
        }
    });

    prefixes
}

/// The 8-byte prefix stored for a word: the first 8 bytes of the digest, right-padded
/// with zeros for shorter digests. `None` if the algorithm rejects the word.
fn hash_prefix(algorithm: &dyn HashAlgorithm, word: &[u8]) -> Option<[u8; 8]> {
    let hash = algorithm.hash(word)?;
    let mut prefix = [0u8; 8];
    let copy_len = hash.len().min(8);
    prefix[..copy_len].copy_from_slice(&hash[..copy_len]);
    Some(prefix)
}

/// Fail if the builder read nothing from a wordlist that was not empty.
///
/// `bytes_read` counts every byte consumed, including lines the algorithm rejected, so
/// reading zero from a file whose metadata reported a non-zero length means the input
/// vanished underneath the builder — it was truncated between the `metadata` call and
/// the first read, and the index that was just written is silently empty.
///
/// This is deliberately keyed on bytes read rather than on entries written: a wordlist
/// whose every word the algorithm rejects legitimately produces zero entries, and
/// erroring on that would reject a correct build.
fn check_wordlist_was_fully_read(bytes_read: u64, file_len: u64, wordlist_path: &Path) -> Result<()> {
    if bytes_read == 0 && file_len > 0 {
        bail!(
            "read 0 bytes from {}, which metadata reported as {} bytes — the wordlist \
             was truncated while the index was being built",
            wordlist_path.display(),
            file_len
        );
    }
    Ok(())
}

/// Whether two paths lead to the same file on disk.
///
/// `canonicalize` resolves `.`, `..` and symlinks, so it catches the ordinary aliases
/// (`words.txt` vs `./words.txt`, or an output symlinked onto the input). On Unix the
/// device and inode are compared as well, which additionally catches a hard link. The
/// output normally does not exist yet, and a path that cannot be canonicalized cannot be
/// an alias of one that can, so failures are answered "not the same file" rather than
/// propagated.
fn is_same_file(a: &Path, b: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let (Ok(a_meta), Ok(b_meta)) = (std::fs::metadata(a), std::fs::metadata(b)) {
            if a_meta.dev() == b_meta.dev() && a_meta.ino() == b_meta.ino() {
                return true;
            }
        }
    }

    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::ENTRY_SIZE;
    use crate::{Md5, Ntlm};
    use tempfile::NamedTempFile;

    fn test_words_path() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("test_data")
            .join("words.txt")
    }

    #[test]
    fn test_build_creates_valid_index() {
        let output = NamedTempFile::new().expect("failed to create temp file");
        let count = IndexBuilder::build(&Md5, &test_words_path(), output.path(), None)
            .expect("build failed");

        assert!(count > 0, "should write at least one entry");

        let file_len = std::fs::metadata(output.path()).expect("metadata").len();
        assert_eq!(
            file_len,
            count * ENTRY_SIZE as u64,
            "file size should be entry_count * ENTRY_SIZE"
        );
    }

    #[test]
    fn test_build_positions_match_byte_offsets() {
        let mut wordlist = NamedTempFile::new().expect("temp file");
        use std::io::Write;
        // "apple\nbanana\n" — apple starts at 0, banana starts at 6
        write!(wordlist, "apple\nbanana\n").expect("write");

        let output = NamedTempFile::new().expect("temp file");
        let count =
            IndexBuilder::build(&Md5, wordlist.path(), output.path(), None).expect("build failed");
        assert_eq!(count, 2);

        let data = std::fs::read(output.path()).expect("read");
        let entry0 = IndexEntry::read_from(&mut &data[0..ENTRY_SIZE]).expect("read entry");
        let entry1 =
            IndexEntry::read_from(&mut &data[ENTRY_SIZE..2 * ENTRY_SIZE]).expect("read entry");

        assert_eq!(entry0.position(), 0, "apple should be at position 0");
        assert_eq!(entry1.position(), 6, "banana should be at position 6");
    }

    #[test]
    fn test_build_hash_prefix_matches() {
        let mut wordlist = NamedTempFile::new().expect("temp file");
        use std::io::Write;
        write!(wordlist, "hello\n").expect("write");

        let output = NamedTempFile::new().expect("temp file");
        IndexBuilder::build(&Md5, wordlist.path(), output.path(), None).expect("build failed");

        let data = std::fs::read(output.path()).expect("read");
        let entry = IndexEntry::read_from(&mut &data[..]).expect("read entry");

        // MD5("hello") = 5d41402abc4b2a76b9719d911017c592
        // First 8 bytes: 5d41402abc4b2a76
        let expected_prefix: [u8; 8] = [0x5d, 0x41, 0x40, 0x2a, 0xbc, 0x4b, 0x2a, 0x76];
        assert_eq!(entry.hash_prefix, expected_prefix);
    }

    #[test]
    fn test_build_handles_non_utf8_words() {
        let mut wordlist = NamedTempFile::new().expect("temp file");
        use std::io::Write;
        // Write binary data: 0xFF 0xFE (invalid UTF-8) followed by newline
        wordlist.write_all(&[0xFF, 0xFE, b'\n']).expect("write");
        // Then a normal word
        wordlist.write_all(b"hello\n").expect("write");

        let output = NamedTempFile::new().expect("temp file");
        let count = IndexBuilder::build(&Md5, wordlist.path(), output.path(), None)
            .expect("build should not fail on non-UTF-8 data");
        assert_eq!(count, 2, "both lines should produce entries");

        // Verify first entry hashes the raw bytes [0xFF, 0xFE]
        let data = std::fs::read(output.path()).expect("read");
        let entry0 = IndexEntry::read_from(&mut &data[0..ENTRY_SIZE]).expect("read entry");

        let expected_hash = Md5.hash(&[0xFF, 0xFE]).expect("md5 should hash any bytes");
        let mut expected_prefix = [0u8; 8];
        expected_prefix.copy_from_slice(&expected_hash[..8]);
        assert_eq!(entry0.hash_prefix, expected_prefix);
    }

    /// A line beginning with `\r` must be indexed as the word without it, the way
    /// createidx.php's two-sided `trim($word, "\n\r")` does. The builder hashes the
    /// trimmed word, so this asserts on the digest actually written to the index --
    /// with the old one-sided trim it was MD5("\rletmein") and the word was
    /// unreachable through a Rust-built index.
    #[test]
    fn test_leading_carriage_return_is_stripped_like_php_trim() {
        let mut wordlist = NamedTempFile::new().expect("temp file");
        use std::io::Write;
        // Line 2 begins with \r; line 3 has leading spaces that must survive.
        wordlist
            .write_all(b"apple\n\rletmein\n  spaced  \n")
            .expect("write");
        wordlist.flush().expect("flush");

        let output = NamedTempFile::new().expect("temp file");
        let entries = IndexBuilder::build(&Md5, wordlist.path(), output.path(), None)
            .expect("build must succeed");
        assert_eq!(entries, 3);

        let index = std::fs::read(output.path()).expect("read index");
        let prefix_at = |n: usize| index[n * ENTRY_SIZE..n * ENTRY_SIZE + 8].to_vec();

        let expect = |word: &str| Md5.hash(word.as_bytes()).expect("md5")[..8].to_vec();

        assert_eq!(prefix_at(0), expect("apple"));
        assert_eq!(
            prefix_at(1),
            expect("letmein"),
            "a leading \\r must be stripped, matching createidx.php"
        );
        assert_ne!(
            prefix_at(1),
            expect("\rletmein"),
            "the untrimmed form must not be what got indexed"
        );
        assert_eq!(
            prefix_at(2),
            expect("  spaced  "),
            "spaces are password bytes and must survive the trim"
        );
    }

    /// Building an index onto its own wordlist truncates the wordlist before a single
    /// byte has been read, and then reports success with zero entries. Refuse instead.
    #[test]
    fn test_build_refuses_to_write_over_its_own_wordlist() {
        let mut wordlist = NamedTempFile::new().expect("temp file");
        use std::io::Write;
        write!(wordlist, "apple\nbanana\n").expect("write");
        wordlist.flush().expect("flush");

        let error = IndexBuilder::build(&Md5, wordlist.path(), wordlist.path(), None)
            .expect_err("building onto the wordlist must fail");
        assert!(
            error.to_string().contains("the same file"),
            "unexpected error: {error}"
        );

        assert_eq!(
            std::fs::read(wordlist.path()).expect("read"),
            b"apple\nbanana\n".to_vec(),
            "the wordlist must be untouched"
        );
    }

    /// Reading nothing from a non-empty wordlist means it was truncated mid-build, and
    /// the index just written is silently empty. That state cannot be produced through
    /// the public API without racing the builder, so the check is asserted directly.
    #[test]
    fn test_truncated_wordlist_is_an_error_but_a_fully_rejected_one_is_not() {
        let path = Path::new("words.txt");

        let error = check_wordlist_was_fully_read(0, 4096, path)
            .expect_err("reading 0 bytes from a 4096-byte file must fail");
        assert_eq!(
            error.to_string(),
            "read 0 bytes from words.txt, which metadata reported as 4096 bytes — \
             the wordlist was truncated while the index was being built"
        );

        // An empty wordlist read as empty is consistent, not a truncation.
        check_wordlist_was_fully_read(0, 0, path).expect("an empty wordlist is not an error");
        // Every byte read, even if every word was rejected and no entry was written.
        check_wordlist_was_fully_read(4096, 4096, path).expect("a fully read wordlist is fine");
        check_wordlist_was_fully_read(1, 4096, path)
            .expect("a partial read is not what this check is for");
    }

    /// The companion property, through the public API: a wordlist the algorithm rejects
    /// in its entirety builds a legitimate empty index rather than tripping the guard.
    /// NTLM rejects non-UTF-8 input, so every line here is skipped.
    #[test]
    fn test_wordlist_rejected_in_its_entirety_builds_an_empty_index() {
        let mut wordlist = NamedTempFile::new().expect("temp file");
        use std::io::Write;
        wordlist.write_all(b"\xff\xfe\n\xff\xfe\xfd\n").expect("write");
        wordlist.flush().expect("flush");

        let output = NamedTempFile::new().expect("temp file");
        let entries = IndexBuilder::build(&Ntlm, wordlist.path(), output.path(), None)
            .expect("a fully rejected wordlist must still build");

        assert_eq!(entries, 0);
        assert_eq!(
            std::fs::metadata(output.path()).expect("index must exist").len(),
            0
        );
    }

    /// The alias does not have to be the identical path string: a symlink resolves to the
    /// same file, and a hard link is the same inode without resolving to the same path.
    #[cfg(unix)]
    #[test]
    fn test_build_refuses_an_output_that_is_a_link_to_the_wordlist() {
        let dir = tempfile::tempdir().expect("temp dir");
        let wordlist_path = dir.path().join("words.txt");
        std::fs::write(&wordlist_path, b"apple\nbanana\n").expect("write wordlist");

        let symlinked = dir.path().join("symlinked.idx");
        std::os::unix::fs::symlink(&wordlist_path, &symlinked).expect("symlink");

        let hardlinked = dir.path().join("hardlinked.idx");
        std::fs::hard_link(&wordlist_path, &hardlinked).expect("hard link");

        for output_path in [&symlinked, &hardlinked] {
            let error = IndexBuilder::build(&Md5, &wordlist_path, output_path, None)
                .expect_err("building onto a link to the wordlist must fail");
            assert!(
                error.to_string().contains("the same file"),
                "unexpected error for {}: {error}",
                output_path.display()
            );
            assert_eq!(
                std::fs::read(&wordlist_path).expect("read"),
                b"apple\nbanana\n".to_vec(),
                "the wordlist must survive {}",
                output_path.display()
            );
        }
    }

    /// Words the algorithm rejects must be omitted from the index entirely, and
    /// must still advance the wordlist position — otherwise every entry after a
    /// rejected word points at the wrong offset. This is the CrackStation bug
    /// where invalid NTLM input was indexed as the hash of the empty string.
    #[test]
    fn test_build_skips_words_the_algorithm_rejects() {
        let mut wordlist = NamedTempFile::new().expect("temp file");
        use std::io::Write;
        // 0xFF 0xFE is not valid UTF-8, so NTLM rejects it. 3 bytes with the \n.
        wordlist.write_all(&[0xFF, 0xFE, b'\n']).expect("write");
        wordlist.write_all(b"hello\n").expect("write");
        wordlist.flush().expect("flush");

        let output = NamedTempFile::new().expect("temp file");
        let count = IndexBuilder::build(&Ntlm, wordlist.path(), output.path(), None)
            .expect("build failed");

        assert_eq!(count, 1, "the rejected word must not produce an entry");

        let data = std::fs::read(output.path()).expect("read");
        assert_eq!(data.len(), ENTRY_SIZE, "index must hold exactly one entry");

        let entry = IndexEntry::read_from(&mut &data[..]).expect("read entry");

        // "hello" starts at byte 3, after the 3-byte rejected line. A skip that
        // forgot to advance the position would leave this at 0.
        assert_eq!(entry.position(), 3);

        let expected_hash = Ntlm.hash(b"hello").expect("ntlm should hash ascii");
        let mut expected_prefix = [0u8; 8];
        expected_prefix.copy_from_slice(&expected_hash[..8]);
        assert_eq!(entry.hash_prefix, expected_prefix);
    }
}
