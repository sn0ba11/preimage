use std::fs::File;
use std::io::{BufReader, BufWriter, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use memmap2::Mmap;
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 8] = b"PIMORD2\0";
const VERSION: u32 = 1;
const HEADER_SIZE: usize = 64;
const CHECKPOINT_SIZE: usize = 16;
pub const DEFAULT_STRIDE: u32 = 65_536;

#[derive(Debug, Clone, Copy)]
struct Header {
    stride: u32,
    dictionary_len: u64,
    dictionary_sha256: [u8; 32],
    accepted_count: u64,
}

impl Header {
    fn encode(self) -> [u8; HEADER_SIZE] {
        let mut bytes = [0u8; HEADER_SIZE];
        bytes[..8].copy_from_slice(MAGIC);
        bytes[8..12].copy_from_slice(&VERSION.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.stride.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.dictionary_len.to_le_bytes());
        bytes[24..56].copy_from_slice(&self.dictionary_sha256);
        bytes[56..64].copy_from_slice(&self.accepted_count.to_le_bytes());
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_SIZE {
            bail!("CloudAP ordinal sidecar header is truncated");
        }
        if &bytes[..8] != MAGIC {
            bail!("not a Preimage CloudAP ordinal sidecar");
        }
        let version = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        if version != VERSION {
            bail!("unsupported CloudAP ordinal sidecar version {version}");
        }
        let stride = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
        if stride == 0 {
            bail!("CloudAP ordinal sidecar has zero checkpoint stride");
        }
        let dictionary_len = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
        let mut dictionary_sha256 = [0u8; 32];
        dictionary_sha256.copy_from_slice(&bytes[24..56]);
        let accepted_count = u64::from_le_bytes(bytes[56..64].try_into().unwrap());
        Ok(Self {
            stride,
            dictionary_len,
            dictionary_sha256,
            accepted_count,
        })
    }
}

pub struct OrdinalIndex {
    path: PathBuf,
    mmap: Mmap,
    header: Header,
}

impl OrdinalIndex {
    pub fn path_for_cache(cache_path: &Path) -> PathBuf {
        let mut value = cache_path.as_os_str().to_os_string();
        value.push(".ord");
        value.into()
    }

    pub fn ensure_for_dictionary(cache_path: &Path, dictionary_path: &Path) -> Result<Self> {
        let path = Self::path_for_cache(cache_path);
        if path.exists() {
            if let Ok(existing) = Self::open(&path, dictionary_path) {
                return Ok(existing);
            }
        }
        Self::build(&path, dictionary_path, DEFAULT_STRIDE)?;
        Self::open(&path, dictionary_path)
    }

    pub fn build(path: &Path, dictionary_path: &Path, stride: u32) -> Result<()> {
        if stride == 0 {
            bail!("CloudAP ordinal checkpoint stride must be non-zero");
        }
        let dictionary_file = File::open(dictionary_path)
            .with_context(|| format!("open dictionary {}", dictionary_path.display()))?;
        let dictionary_len = dictionary_file.metadata()?.len();
        let dictionary_sha256: [u8; 32] = if dictionary_len == 0 {
            Sha256::digest([]).into()
        } else {
            // SAFETY: same static-input assumption as cache/index builders.
            let mmap = unsafe { Mmap::map(&dictionary_file)? };
            Sha256::digest(&mmap).into()
        };

        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let tmp = {
            let mut value = path.as_os_str().to_os_string();
            value.push(".part");
            PathBuf::from(value)
        };
        let mut writer = BufWriter::new(File::create(&tmp)?);
        writer.write_all(&[0u8; HEADER_SIZE])?;

        let mut reader = BufReader::with_capacity(8 << 20, File::open(dictionary_path)?);
        let mut accepted = 0u64;
        let mut byte_offset = 0u64;
        let mut line = Vec::new();

        loop {
            line.clear();
            let read = std::io::BufRead::read_until(&mut reader, b'\n', &mut line)?;
            if read == 0 {
                break;
            }
            let line_start = byte_offset;
            byte_offset += read as u64;
            let word = trim_record_separators(&line);
            if std::str::from_utf8(word).is_ok() {
                if accepted % stride as u64 == 0 {
                    writer.write_all(&accepted.to_le_bytes())?;
                    writer.write_all(&line_start.to_le_bytes())?;
                }
                accepted += 1;
            }
        }

        let header = Header {
            stride,
            dictionary_len,
            dictionary_sha256,
            accepted_count: accepted,
        };
        writer.flush()?;
        let mut file = writer.into_inner().map_err(|e| e.into_error())?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&header.encode())?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn open(path: &Path, dictionary_path: &Path) -> Result<Self> {
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        if len < HEADER_SIZE as u64 {
            bail!("CloudAP ordinal sidecar is shorter than its header");
        }
        // SAFETY: read-only immutable sidecar.
        let mmap = unsafe { Mmap::map(&file)? };
        let header = Header::decode(&mmap[..HEADER_SIZE])?;

        let expected_checkpoints = if header.accepted_count == 0 {
            0
        } else {
            (header.accepted_count - 1) / header.stride as u64 + 1
        };
        let expected_len = HEADER_SIZE as u64 + expected_checkpoints * CHECKPOINT_SIZE as u64;
        if len != expected_len {
            bail!(
                "CloudAP ordinal sidecar length mismatch: expected {expected_len} bytes, found {len}"
            );
        }

        let dictionary_file = File::open(dictionary_path)?;
        let dictionary_len = dictionary_file.metadata()?.len();
        if dictionary_len != header.dictionary_len {
            bail!("dictionary size does not match CloudAP ordinal sidecar");
        }
        let digest: [u8; 32] = if dictionary_len == 0 {
            Sha256::digest([]).into()
        } else {
            // SAFETY: read-only static dictionary.
            let dictionary_mmap = unsafe { Mmap::map(&dictionary_file)? };
            Sha256::digest(&dictionary_mmap).into()
        };
        if digest != header.dictionary_sha256 {
            bail!("dictionary SHA-256 does not match CloudAP ordinal sidecar");
        }

        Ok(Self {
            path: path.to_path_buf(),
            mmap,
            header,
        })
    }

    pub fn accepted_count(&self) -> u64 {
        self.header.accepted_count
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn resume_offset(&self, dictionary: &[u8], next_ordinal: u64) -> Result<u64> {
        if next_ordinal == self.header.accepted_count {
            return Ok(dictionary.len() as u64);
        }
        self.resolve_offset(dictionary, next_ordinal)
    }

    pub fn resolve_offset(&self, dictionary: &[u8], ordinal: u64) -> Result<u64> {
        if ordinal >= self.header.accepted_count {
            bail!(
                "CloudAP accepted-candidate ordinal {ordinal} is outside {} candidates",
                self.header.accepted_count
            );
        }
        let checkpoint_index = ordinal / self.header.stride as u64;
        let checkpoint_start =
            HEADER_SIZE + checkpoint_index as usize * CHECKPOINT_SIZE;
        let stored_ordinal = u64::from_le_bytes(
            self.mmap[checkpoint_start..checkpoint_start + 8]
                .try_into()
                .unwrap(),
        );
        let offset = u64::from_le_bytes(
            self.mmap[checkpoint_start + 8..checkpoint_start + 16]
                .try_into()
                .unwrap(),
        );
        resolve_from_checkpoint(dictionary, stored_ordinal, offset, ordinal)
    }
}

fn resolve_from_checkpoint(
    dictionary: &[u8],
    mut ordinal: u64,
    mut offset: u64,
    target: u64,
) -> Result<u64> {
    while ordinal <= target {
        let start = usize::try_from(offset).context("dictionary offset does not fit platform")?;
        if start >= dictionary.len() {
            bail!("CloudAP ordinal sidecar points outside dictionary");
        }
        let next = dictionary[start..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|relative| start + relative + 1)
            .unwrap_or(dictionary.len());
        let line_end = if next > start && dictionary[next.saturating_sub(1)] == b'\n' {
            next - 1
        } else {
            next
        };
        let word = trim_record_separators(&dictionary[start..line_end]);
        if std::str::from_utf8(word).is_ok() {
            if ordinal == target {
                return Ok(offset);
            }
            ordinal += 1;
        }
        offset = next as u64;
    }
    bail!("CloudAP ordinal sidecar could not resolve candidate ordinal {target}")
}

fn trim_record_separators(mut word: &[u8]) -> &[u8] {
    while matches!(word.first(), Some(b'\r' | b'\n')) {
        word = &word[1..];
    }
    while matches!(word.last(), Some(b'\r' | b'\n')) {
        word = &word[..word.len() - 1];
    }
    word
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn builds_and_resolves_accepted_candidate_ordinals() {
        let dir = tempdir().unwrap();
        let dict = dir.path().join("words.txt");
        let sidecar = dir.path().join("words.ord");
        std::fs::write(
            &dict,
            b"zero\n\xff\xfe\none\n\r\ntwo\nthree",
        )
        .unwrap();

        OrdinalIndex::build(&sidecar, &dict, 2).unwrap();
        let index = OrdinalIndex::open(&sidecar, &dict).unwrap();
        assert_eq!(index.accepted_count(), 5);

        let bytes = std::fs::read(&dict).unwrap();
        for (ordinal, expected) in [
            (0, 0u64),
            (1, b"zero\n\xff\xfe\n".len() as u64),
            (2, b"zero\n\xff\xfe\none\n".len() as u64),
            (3, b"zero\n\xff\xfe\none\n\r\n".len() as u64),
            (4, b"zero\n\xff\xfe\none\n\r\ntwo\n".len() as u64),
        ] {
            assert_eq!(index.resolve_offset(&bytes, ordinal).unwrap(), expected);
        }
    }

    #[test]
    fn rejects_changed_dictionary() {
        let dir = tempdir().unwrap();
        let dict = dir.path().join("words.txt");
        let sidecar = dir.path().join("words.ord");
        std::fs::write(&dict, b"one\ntwo\n").unwrap();
        OrdinalIndex::build(&sidecar, &dict, 2).unwrap();
        std::fs::write(&dict, b"one\nsix\n").unwrap();
        assert!(OrdinalIndex::open(&sidecar, &dict).is_err());
    }
}
