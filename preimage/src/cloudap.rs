//! Reusable CloudAP / Hashcat mode 33700 KDF caches.
//!
//! CloudAP CacheData mode 33700 derives an AES-256 key with
//! PBKDF2-HMAC-SHA256 over the UTF-16LE password, an empty salt, and the
//! iteration count embedded in the target (10,000 for current Windows
//! CacheData). Because the KDF has no per-target salt, that expensive derived
//! key can be computed once per dictionary candidate and reused against future
//! CacheData targets. A cache is therefore deliberately *not* a sorted hash
//! index: the target does not expose the derived key. Scanning streams the
//! precomputed keys and performs only the cheap target-specific AES marker
//! check.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use aes::cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit};
use aes::Aes256;
use anyhow::{bail, Context, Result};
use indicatif::ProgressBar;
use memmap2::Mmap;
use pbkdf2::pbkdf2_hmac;
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 8] = b"PIMC337\0";
const VERSION: u32 = 1;
const HEADER_SIZE: usize = 64;
const RECORD_SIZE: usize = 38;
const KEY_SIZE: usize = 32;
const OFFSET_SIZE: usize = 6;
const DEFAULT_WINDOW_BYTES: usize = 4 << 20;
const CLOUDAP_MARKER: &[u8; 8] = b"\x00\x00\x00\x00\x01\x00\x00\x00";
const MAX_DICTIONARY_OFFSET: u64 = 1u64 << 48;

/// Current Windows CloudAP mode-33700 iteration count.
pub const DEFAULT_CLOUDAP_ITERATIONS: u32 = 10_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudapTarget {
    pub iterations: u32,
    encrypted_first_block: [u8; 16],
}

impl CloudapTarget {
    /// Parse Spectre/Hashcat's `$MSONLINEACCOUNT$0$<iterations>$<ciphertext>` form.
    pub fn parse(value: &str) -> Result<Self> {
        let parts: Vec<&str> = value.trim().split('$').collect();
        if parts.len() != 5
            || !parts[0].is_empty()
            || parts[1] != "MSONLINEACCOUNT"
            || parts[2] != "0"
        {
            bail!("not a supported $MSONLINEACCOUNT$0$ CloudAP target");
        }
        let iterations: u32 = parts[3]
            .parse()
            .context("CloudAP target has an invalid iteration count")?;
        if iterations == 0 {
            bail!("CloudAP target iteration count must be non-zero");
        }
        let ciphertext = hex::decode(parts[4]).context("CloudAP target ciphertext is not hex")?;
        if ciphertext.len() != 32 {
            bail!("CloudAP mode-33700 target ciphertext must be exactly 32 bytes");
        }
        let mut encrypted_first_block = [0u8; 16];
        encrypted_first_block.copy_from_slice(&ciphertext[..16]);
        Ok(Self {
            iterations,
            encrypted_first_block,
        })
    }

    /// Verify one already-derived 32-byte candidate key.
    pub fn verify_derived_key(&self, key: &[u8; KEY_SIZE]) -> bool {
        let cipher = Aes256::new(GenericArray::from_slice(key));
        let mut block = GenericArray::clone_from_slice(&self.encrypted_first_block);
        // CloudAP's first CBC block uses an all-zero IV, therefore decrypting the
        // first block is exactly AES-ECB decrypt followed by XOR with zero.
        cipher.decrypt_block(&mut block);
        &block[..CLOUDAP_MARKER.len()] == CLOUDAP_MARKER
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudapMatch {
    pub dictionary_offset: u64,
    pub plaintext: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudapBuildStats {
    pub records: u64,
    pub invalid_utf8_lines: u64,
    pub resumed_records: u64,
    pub dictionary_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Header {
    iterations: u32,
    dictionary_len: u64,
    dictionary_sha256: [u8; 32],
    record_count: u64,
}

impl Header {
    fn encode(&self) -> [u8; HEADER_SIZE] {
        let mut bytes = [0u8; HEADER_SIZE];
        bytes[0..8].copy_from_slice(MAGIC);
        bytes[8..12].copy_from_slice(&VERSION.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.iterations.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.dictionary_len.to_le_bytes());
        bytes[24..56].copy_from_slice(&self.dictionary_sha256);
        bytes[56..64].copy_from_slice(&self.record_count.to_le_bytes());
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_SIZE {
            bail!("CloudAP cache header is truncated");
        }
        if &bytes[..8] != MAGIC {
            bail!("not a Preimage CloudAP cache");
        }
        let version = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        if version != VERSION {
            bail!("unsupported CloudAP cache version {version}");
        }
        let iterations = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
        let dictionary_len = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
        let mut dictionary_sha256 = [0u8; 32];
        dictionary_sha256.copy_from_slice(&bytes[24..56]);
        let record_count = u64::from_le_bytes(bytes[56..64].try_into().unwrap());
        Ok(Self {
            iterations,
            dictionary_len,
            dictionary_sha256,
            record_count,
        })
    }
}

/// A completed, dictionary-bound cache of CloudAP PBKDF2-derived keys.
pub struct CloudapCache {
    cache_path: PathBuf,
    dictionary_path: PathBuf,
    header: Header,
    cache_mmap: Mmap,
    dictionary_mmap: Option<Mmap>,
}

impl CloudapCache {
    /// Build a reusable cache. If `<output>.part` exists, a compatible partial
    /// build is resumed from its last complete record. Set `fresh` to discard
    /// both the completed output and any partial file first.
    pub fn build(
        dictionary_path: &Path,
        output_path: &Path,
        iterations: u32,
        threads: usize,
        fresh: bool,
        progress: Option<&ProgressBar>,
    ) -> Result<CloudapBuildStats> {
        if iterations == 0 {
            bail!("CloudAP iteration count must be non-zero");
        }
        let dictionary_file = File::open(dictionary_path)
            .with_context(|| format!("open dictionary {}", dictionary_path.display()))?;
        let dictionary_len = dictionary_file.metadata()?.len();
        if dictionary_len >= MAX_DICTIONARY_OFFSET {
            bail!("dictionary is too large for the 48-bit cache offset format");
        }
        if output_path.exists() && !fresh {
            bail!(
                "CloudAP cache {} already exists; use --fresh to replace it",
                output_path.display()
            );
        }
        if same_file(dictionary_path, output_path) {
            bail!("refusing to overwrite the dictionary with the CloudAP cache");
        }

        if dictionary_len == 0 {
            // Mapping an empty file is platform-dependent. Its SHA-256 is stable.
            return build_empty_cache(dictionary_path, output_path, iterations, fresh);
        }

        // SAFETY: same static-input assumption as the regular Preimage builder.
        let dictionary_mmap = unsafe { Mmap::map(&dictionary_file)? };
        let dictionary_sha256: [u8; 32] = Sha256::digest(&dictionary_mmap).into();
        let expected_header = Header {
            iterations,
            dictionary_len,
            dictionary_sha256,
            record_count: 0,
        };
        let partial_path = partial_path(output_path);

        if fresh {
            let _ = std::fs::remove_file(output_path);
            let _ = std::fs::remove_file(&partial_path);
        }
        if let Some(parent) = output_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let mut partial = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&partial_path)
            .with_context(|| format!("open partial cache {}", partial_path.display()))?;

        let (resumed_records, start_offset) = prepare_partial(
            &mut partial,
            &expected_header,
            &dictionary_mmap,
            dictionary_len,
        )?;
        let mut records = resumed_records;
        let mut invalid_utf8_lines = 0u64;

        if let Some(pb) = progress {
            pb.set_length(dictionary_len);
            pb.set_position(start_offset);
        }

        partial.seek(SeekFrom::End(0))?;
        let mut output = BufWriter::with_capacity(8 << 20, partial);
        let worker_count = if threads == 0 {
            std::thread::available_parallelism()
                .map(|value| value.get())
                .unwrap_or(1)
        } else {
            threads.max(1)
        };

        let data: &[u8] = &dictionary_mmap;
        let mut wstart = start_offset as usize;
        while wstart < data.len() {
            let target = (wstart + DEFAULT_WINDOW_BYTES).min(data.len());
            let wend = line_aligned_end(data, target);
            let ranges = split_line_ranges(data, wstart, wend, worker_count);
            let chunks = std::thread::scope(|scope| {
                let handles: Vec<_> = ranges
                    .iter()
                    .map(|&(start, end)| {
                        scope.spawn(move || process_range(data, start, end, iterations))
                    })
                    .collect();
                handles
                    .into_iter()
                    .map(|handle| handle.join().expect("CloudAP KDF worker panicked"))
                    .collect::<Vec<_>>()
            });

            for chunk in chunks {
                output.write_all(&chunk.bytes)?;
                records += chunk.records;
                invalid_utf8_lines += chunk.invalid_utf8_lines;
            }
            // Make resumable progress durable at every bounded window. An interrupted
            // write is repaired to the last complete fixed-size record on resume.
            output.flush()?;
            if let Some(pb) = progress {
                pb.set_position(wend as u64);
            }
            wstart = wend;
        }

        let mut partial = output.into_inner().map_err(|e| e.into_error())?;
        let final_header = Header {
            record_count: records,
            ..expected_header
        };
        partial.seek(SeekFrom::Start(0))?;
        partial.write_all(&final_header.encode())?;
        partial.sync_all()?;
        drop(partial);
        std::fs::rename(&partial_path, output_path).with_context(|| {
            format!(
                "finalize CloudAP cache {} -> {}",
                partial_path.display(),
                output_path.display()
            )
        })?;

        Ok(CloudapBuildStats {
            records,
            invalid_utf8_lines,
            resumed_records,
            dictionary_bytes: dictionary_len,
        })
    }

    /// Open and strongly bind a completed cache to the exact dictionary used to
    /// build it (length + full SHA-256).
    pub fn open(cache_path: &Path, dictionary_path: &Path) -> Result<Self> {
        let cache_file = File::open(cache_path)
            .with_context(|| format!("open CloudAP cache {}", cache_path.display()))?;
        let cache_len = cache_file.metadata()?.len();
        if cache_len < HEADER_SIZE as u64 {
            bail!("CloudAP cache is shorter than its header");
        }
        // SAFETY: read-only static cache under the same trust model as Preimage indexes.
        let cache_mmap = unsafe { Mmap::map(&cache_file)? };
        let header = Header::decode(&cache_mmap[..HEADER_SIZE])?;
        let expected_len = HEADER_SIZE as u64
            + header
                .record_count
                .checked_mul(RECORD_SIZE as u64)
                .context("CloudAP record count overflows file length")?;
        if cache_len != expected_len {
            bail!(
                "CloudAP cache length mismatch: header declares {} records ({} bytes total), file is {} bytes",
                header.record_count,
                expected_len,
                cache_len
            );
        }

        let dictionary_file = File::open(dictionary_path)
            .with_context(|| format!("open dictionary {}", dictionary_path.display()))?;
        let dictionary_len = dictionary_file.metadata()?.len();
        if dictionary_len != header.dictionary_len {
            bail!("dictionary size does not match the CloudAP cache header");
        }
        let dictionary_mmap = if dictionary_len == 0 {
            let digest: [u8; 32] = Sha256::digest([]).into();
            if digest != header.dictionary_sha256 {
                bail!("dictionary SHA-256 does not match the CloudAP cache header");
            }
            None
        } else {
            // SAFETY: read-only static dictionary.
            let mmap = unsafe { Mmap::map(&dictionary_file)? };
            let digest: [u8; 32] = Sha256::digest(&mmap).into();
            if digest != header.dictionary_sha256 {
                bail!("dictionary SHA-256 does not match the CloudAP cache header");
            }
            Some(mmap)
        };

        Ok(Self {
            cache_path: cache_path.to_path_buf(),
            dictionary_path: dictionary_path.to_path_buf(),
            header,
            cache_mmap,
            dictionary_mmap,
        })
    }

    pub fn iterations(&self) -> u32 {
        self.header.iterations
    }

    pub fn record_count(&self) -> u64 {
        self.header.record_count
    }

    pub fn cache_path(&self) -> &Path {
        &self.cache_path
    }

    pub fn dictionary_path(&self) -> &Path {
        &self.dictionary_path
    }

    /// Sequentially scan prederived keys against one CloudAP target. `limit == 0`
    /// returns every match; otherwise scanning stops after `limit` matches.
    pub fn scan(
        &self,
        target: &CloudapTarget,
        limit: usize,
        progress: Option<&ProgressBar>,
    ) -> Result<Vec<CloudapMatch>> {
        if target.iterations != self.header.iterations {
            bail!(
                "target uses {} iterations but this cache was built for {}",
                target.iterations,
                self.header.iterations
            );
        }
        if let Some(pb) = progress {
            pb.set_length(self.header.record_count);
            pb.set_position(0);
        }

        let records = &self.cache_mmap[HEADER_SIZE..];
        let record_count = usize::try_from(self.header.record_count)
            .context("CloudAP record count does not fit this platform")?;
        let mut matches = Vec::new();
        for index in 0..record_count {
            let start = index * RECORD_SIZE;
            let record = &records[start..start + RECORD_SIZE];
            let mut key = [0u8; KEY_SIZE];
            key.copy_from_slice(&record[..KEY_SIZE]);
            if target.verify_derived_key(&key) {
                let offset = decode_offset(&record[KEY_SIZE..KEY_SIZE + OFFSET_SIZE]);
                let dictionary = self
                    .dictionary_mmap
                    .as_deref()
                    .context("CloudAP cache matched a key but its dictionary is empty")?;
                let plaintext = dictionary_word(dictionary, offset)?;
                matches.push(CloudapMatch {
                    dictionary_offset: offset,
                    plaintext,
                });
                if limit != 0 && matches.len() >= limit {
                    if let Some(pb) = progress {
                        pb.set_position(index as u64 + 1);
                    }
                    break;
                }
            }
            if let Some(pb) = progress {
                if index & 0x3fff == 0 {
                    pb.set_position(index as u64 + 1);
                }
            }
        }
        Ok(matches)
    }

    /// Verify structure and dictionary binding without scanning a target.
    pub fn check(cache_path: &Path, dictionary_path: &Path) -> Result<(u64, u32)> {
        let cache = Self::open(cache_path, dictionary_path)?;
        Ok((cache.record_count(), cache.iterations()))
    }
}

#[derive(Default)]
struct ProcessedChunk {
    bytes: Vec<u8>,
    records: u64,
    invalid_utf8_lines: u64,
}

fn process_range(data: &[u8], start: usize, end: usize, iterations: u32) -> ProcessedChunk {
    let mut result = ProcessedChunk::default();
    let mut pos = start;
    let mut utf16 = Vec::with_capacity(128);
    while pos < end {
        let (line_end, next) = match data[pos..end].iter().position(|&byte| byte == b'\n') {
            Some(relative) => (pos + relative, pos + relative + 1),
            None => (end, end),
        };
        let mut word = &data[pos..line_end];
        while matches!(word.first(), Some(b'\r' | b'\n')) {
            word = &word[1..];
        }
        while matches!(word.last(), Some(b'\r' | b'\n')) {
            word = &word[..word.len() - 1];
        }
        match std::str::from_utf8(word) {
            Ok(password) => {
                utf16.clear();
                utf16.reserve(password.len() * 2);
                for unit in password.encode_utf16() {
                    utf16.extend_from_slice(&unit.to_le_bytes());
                }
                let mut key = [0u8; KEY_SIZE];
                pbkdf2_hmac::<Sha256>(&utf16, b"", iterations, &mut key);
                result.bytes.extend_from_slice(&key);
                encode_offset(pos as u64, &mut result.bytes);
                result.records += 1;
            }
            Err(_) => result.invalid_utf8_lines += 1,
        }
        pos = next;
    }
    result
}

fn prepare_partial(
    partial: &mut File,
    expected_header: &Header,
    dictionary: &[u8],
    dictionary_len: u64,
) -> Result<(u64, u64)> {
    let len = partial.metadata()?.len();
    if len == 0 {
        partial.write_all(&expected_header.encode())?;
        partial.sync_data()?;
        return Ok((0, 0));
    }
    if len < HEADER_SIZE as u64 {
        bail!("partial CloudAP cache header is truncated; use --fresh to rebuild it");
    }
    partial.seek(SeekFrom::Start(0))?;
    let mut header_bytes = [0u8; HEADER_SIZE];
    partial.read_exact(&mut header_bytes)?;
    let existing = Header::decode(&header_bytes)?;
    if existing.iterations != expected_header.iterations
        || existing.dictionary_len != expected_header.dictionary_len
        || existing.dictionary_sha256 != expected_header.dictionary_sha256
    {
        bail!("partial CloudAP cache belongs to a different dictionary/KDF; use --fresh");
    }

    let payload_len = len - HEADER_SIZE as u64;
    let complete_payload = payload_len / RECORD_SIZE as u64 * RECORD_SIZE as u64;
    let repaired_len = HEADER_SIZE as u64 + complete_payload;
    if repaired_len != len {
        partial.set_len(repaired_len)?;
    }
    let records = complete_payload / RECORD_SIZE as u64;
    if records == 0 {
        return Ok((0, 0));
    }

    partial.seek(SeekFrom::Start(
        HEADER_SIZE as u64 + (records - 1) * RECORD_SIZE as u64 + KEY_SIZE as u64,
    ))?;
    let mut offset_bytes = [0u8; OFFSET_SIZE];
    partial.read_exact(&mut offset_bytes)?;
    let last_offset = decode_offset(&offset_bytes);
    if last_offset >= dictionary_len {
        bail!("partial CloudAP cache contains an invalid dictionary offset; use --fresh");
    }
    let start = next_line_offset(dictionary, last_offset as usize) as u64;
    Ok((records, start))
}

fn build_empty_cache(
    dictionary_path: &Path,
    output_path: &Path,
    iterations: u32,
    fresh: bool,
) -> Result<CloudapBuildStats> {
    if output_path.exists() && !fresh {
        bail!("CloudAP cache {} already exists", output_path.display());
    }
    let digest: [u8; 32] = Sha256::digest([]).into();
    let header = Header {
        iterations,
        dictionary_len: 0,
        dictionary_sha256: digest,
        record_count: 0,
    };
    if same_file(dictionary_path, output_path) {
        bail!("refusing to overwrite the dictionary with the CloudAP cache");
    }
    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(output_path, header.encode())?;
    Ok(CloudapBuildStats {
        records: 0,
        invalid_utf8_lines: 0,
        resumed_records: 0,
        dictionary_bytes: 0,
    })
}

fn dictionary_word(data: &[u8], offset: u64) -> Result<String> {
    let start = usize::try_from(offset).context("dictionary offset does not fit this platform")?;
    if start >= data.len() {
        bail!("CloudAP cache record points outside the dictionary");
    }
    let end = data[start..]
        .iter()
        .position(|&byte| byte == b'\n')
        .map(|relative| start + relative)
        .unwrap_or(data.len());
    let mut word = &data[start..end];
    while matches!(word.first(), Some(b'\r' | b'\n')) {
        word = &word[1..];
    }
    while matches!(word.last(), Some(b'\r' | b'\n')) {
        word = &word[..word.len() - 1];
    }
    Ok(std::str::from_utf8(word)
        .context("cached dictionary candidate is no longer valid UTF-8")?
        .to_owned())
}

fn encode_offset(offset: u64, output: &mut Vec<u8>) {
    debug_assert!(offset < MAX_DICTIONARY_OFFSET);
    let bytes = offset.to_le_bytes();
    output.extend_from_slice(&bytes[..OFFSET_SIZE]);
}

fn decode_offset(bytes: &[u8]) -> u64 {
    let mut full = [0u8; 8];
    full[..OFFSET_SIZE].copy_from_slice(&bytes[..OFFSET_SIZE]);
    u64::from_le_bytes(full)
}

fn line_aligned_end(data: &[u8], target: usize) -> usize {
    if target >= data.len() {
        return data.len();
    }
    data[target..]
        .iter()
        .position(|&byte| byte == b'\n')
        .map(|relative| target + relative + 1)
        .unwrap_or(data.len())
}

fn next_line_offset(data: &[u8], start: usize) -> usize {
    data[start..]
        .iter()
        .position(|&byte| byte == b'\n')
        .map(|relative| start + relative + 1)
        .unwrap_or(data.len())
}

fn split_line_ranges(data: &[u8], start: usize, end: usize, parts: usize) -> Vec<(usize, usize)> {
    let parts = parts.max(1);
    let span = end - start;
    let mut bounds = Vec::with_capacity(parts + 1);
    bounds.push(start);
    for index in 1..parts {
        let target = start + span * index / parts;
        let previous = *bounds.last().unwrap();
        bounds.push(line_aligned_end(data, target).min(end).max(previous));
    }
    bounds.push(end);
    bounds.windows(2).map(|pair| (pair[0], pair[1])).collect()
}

fn partial_path(output_path: &Path) -> PathBuf {
    let mut value = output_path.as_os_str().to_os_string();
    value.push(".part");
    value.into()
}

fn same_file(a: &Path, b: &Path) -> bool {
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
    use aes::cipher::{BlockEncrypt, KeyInit};
    use tempfile::tempdir;

    fn target_for(password: &str, iterations: u32) -> String {
        let mut utf16 = Vec::new();
        for unit in password.encode_utf16() {
            utf16.extend_from_slice(&unit.to_le_bytes());
        }
        let mut key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(&utf16, b"", iterations, &mut key);
        let cipher = Aes256::new(GenericArray::from_slice(&key));
        let mut block = GenericArray::clone_from_slice(b"\x00\x00\x00\x00\x01\x00\x00\x00fixture!");
        cipher.encrypt_block(&mut block);
        let mut ciphertext = [0u8; 32];
        ciphertext[..16].copy_from_slice(&block);
        format!(
            "$MSONLINEACCOUNT$0${iterations}${}",
            hex::encode(ciphertext)
        )
    }

    #[test]
    fn matches_hashcat_mode_33700_self_test_vector() {
        let target = CloudapTarget::parse(
            "$MSONLINEACCOUNT$0$10000$91869d1d5d3a1df25dd3f0e57bbc226a43641bc03086dcb5b6672941fcabce01",
        )
        .unwrap();
        let mut utf16 = Vec::new();
        for unit in "hashcat".encode_utf16() {
            utf16.extend_from_slice(&unit.to_le_bytes());
        }
        let mut key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(&utf16, b"", 10_000, &mut key);
        assert!(target.verify_derived_key(&key));
    }

    #[test]
    fn parses_and_verifies_target() {
        let target = CloudapTarget::parse(&target_for("CorrectHorse", 8)).unwrap();
        let mut utf16 = Vec::new();
        for unit in "CorrectHorse".encode_utf16() {
            utf16.extend_from_slice(&unit.to_le_bytes());
        }
        let mut good = [0u8; 32];
        pbkdf2_hmac::<Sha256>(&utf16, b"", 8, &mut good);
        assert!(target.verify_derived_key(&good));
        assert!(!target.verify_derived_key(&[0u8; 32]));
    }

    #[test]
    fn build_open_and_scan_round_trip() {
        let dir = tempdir().unwrap();
        let words = dir.path().join("words.txt");
        let cache = dir.path().join("cloudap33700.pim");
        std::fs::write(&words, b"wrong\nCorrectHorse\nanother\n").unwrap();
        let stats = CloudapCache::build(&words, &cache, 8, 2, false, None).unwrap();
        assert_eq!(stats.records, 3);
        assert_eq!(stats.invalid_utf8_lines, 0);
        let opened = CloudapCache::open(&cache, &words).unwrap();
        let target = CloudapTarget::parse(&target_for("CorrectHorse", 8)).unwrap();
        let found = opened.scan(&target, 1, None).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].plaintext, "CorrectHorse");
    }

    #[test]
    fn cache_is_bound_to_dictionary_sha256() {
        let dir = tempdir().unwrap();
        let words = dir.path().join("words.txt");
        let cache = dir.path().join("cloudap33700.pim");
        std::fs::write(&words, b"one\ntwo\n").unwrap();
        CloudapCache::build(&words, &cache, 4, 1, false, None).unwrap();
        std::fs::write(&words, b"one\nsix\n").unwrap(); // same length, different bytes
        let error = CloudapCache::open(&cache, &words).err().unwrap();
        assert!(error.to_string().contains("SHA-256"));
    }

    #[test]
    fn empty_dictionary_builds_and_reopens_as_zero_record_cache() {
        let dir = tempdir().unwrap();
        let words = dir.path().join("empty.txt");
        let cache = dir.path().join("nested").join("cloudap33700.pim");
        std::fs::write(&words, b"").unwrap();
        let stats = CloudapCache::build(&words, &cache, 4, 1, false, None).unwrap();
        assert_eq!(stats.records, 0);
        assert_eq!(CloudapCache::check(&cache, &words).unwrap(), (0, 4));
        let opened = CloudapCache::open(&cache, &words).unwrap();
        let target = CloudapTarget::parse(&target_for("anything", 4)).unwrap();
        assert!(opened.scan(&target, 1, None).unwrap().is_empty());
    }

    #[test]
    fn invalid_utf8_is_skipped_and_reported() {
        let dir = tempdir().unwrap();
        let words = dir.path().join("words.txt");
        let cache = dir.path().join("cloudap33700.pim");
        std::fs::write(&words, b"valid\n\xff\xfe\nvalid2\n").unwrap();
        let stats = CloudapCache::build(&words, &cache, 2, 2, false, None).unwrap();
        assert_eq!(stats.records, 2);
        assert_eq!(stats.invalid_utf8_lines, 1);
    }

    #[test]
    fn rejects_iteration_mismatch() {
        let dir = tempdir().unwrap();
        let words = dir.path().join("words.txt");
        let cache = dir.path().join("cloudap33700.pim");
        std::fs::write(&words, b"password\n").unwrap();
        CloudapCache::build(&words, &cache, 4, 1, false, None).unwrap();
        let opened = CloudapCache::open(&cache, &words).unwrap();
        let target = CloudapTarget::parse(&target_for("password", 8)).unwrap();
        assert!(opened.scan(&target, 1, None).is_err());
    }

    #[test]
    fn resumes_partial_build_and_repairs_torn_record() {
        let dir = tempdir().unwrap();
        let words = dir.path().join("words.txt");
        let cache = dir.path().join("cloudap33700.pim");
        let data = b"first\nsecond\nthird\n";
        std::fs::write(&words, data).unwrap();

        let digest: [u8; 32] = Sha256::digest(data).into();
        let header = Header {
            iterations: 4,
            dictionary_len: data.len() as u64,
            dictionary_sha256: digest,
            record_count: 0,
        };
        let first_end = data.iter().position(|&byte| byte == b'\n').unwrap() + 1;
        let first = process_range(data, 0, first_end, 4);
        assert_eq!(first.records, 1);

        let part = partial_path(&cache);
        let mut partial_bytes = header.encode().to_vec();
        partial_bytes.extend_from_slice(&first.bytes);
        partial_bytes.extend_from_slice(b"torn!");
        std::fs::write(&part, partial_bytes).unwrap();

        let stats = CloudapCache::build(&words, &cache, 4, 2, false, None).unwrap();
        assert_eq!(stats.resumed_records, 1);
        assert_eq!(stats.records, 3);
        assert!(!part.exists());
        assert_eq!(CloudapCache::check(&cache, &words).unwrap(), (3, 4));
    }

    #[test]
    fn target_parser_rejects_wrong_mode_and_short_ciphertext() {
        assert!(CloudapTarget::parse("$DPAPImk$2*1*sid").is_err());
        assert!(CloudapTarget::parse("$MSONLINEACCOUNT$0$10000$00").is_err());
        assert!(CloudapTarget::parse(
            "$MSONLINEACCOUNT$0$10000$00112233445566778899aabbccddeeff"
        )
        .is_err());
    }
}
