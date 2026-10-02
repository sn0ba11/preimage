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

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};

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
const SCAN_CHUNK_RECORDS: usize = 1 << 16;
const CLOUDAP_MARKER: &[u8; 8] = b"\x00\x00\x00\x00\x01\x00\x00\x00";
const MAX_DICTIONARY_OFFSET: u64 = 1u64 << 48;

/// Current Windows CloudAP mode-33700 iteration count.
pub const DEFAULT_CLOUDAP_ITERATIONS: u32 = 10_000;

/// KDF implementation used while building a CloudAP cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudapBuildBackend {
    /// Use CUDA when this binary was built with nvcc and a device is available.
    Auto,
    /// Use the portable, parallel CPU implementation.
    Cpu,
    /// Require CUDA; return an error instead of silently falling back.
    Cuda,
}

impl fmt::Display for CloudapBuildBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Auto => "auto",
            Self::Cpu => "cpu",
            Self::Cuda => "cuda",
        })
    }
}

impl FromStr for CloudapBuildBackend {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "cpu" => Ok(Self::Cpu),
            "cuda" => Ok(Self::Cuda),
            _ => bail!("unknown CloudAP build backend {value:?}; use auto, cpu, or cuda"),
        }
    }
}

/// Whether this binary contains the optional nvcc-built CUDA kernel.
pub const fn cloudap_cuda_compiled() -> bool {
    cfg!(preimage_cuda)
}

/// Return the number of usable CUDA devices, or zero when CUDA was not compiled in.
pub fn cloudap_cuda_device_count() -> Result<usize> {
    cuda_device_count()
}

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

    fn verify_derived_key_bytes(&self, key: &[u8]) -> bool {
        let key: &[u8; KEY_SIZE] = key
            .try_into()
            .expect("CloudAP cache key slice has the fixed key size");
        self.verify_derived_key(key)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudapMatch {
    pub dictionary_offset: u64,
    pub plaintext: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloudapBuildStats {
    pub backend: CloudapBuildBackend,
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
        Self::build_with_backend(
            dictionary_path,
            output_path,
            iterations,
            threads,
            fresh,
            CloudapBuildBackend::Cpu,
            progress,
        )
    }

    /// Build with an explicitly selected CPU/CUDA policy. `Auto` selects CUDA
    /// only when the binary contains the kernel and a device is available.
    pub fn build_with_backend(
        dictionary_path: &Path,
        output_path: &Path,
        iterations: u32,
        threads: usize,
        fresh: bool,
        backend: CloudapBuildBackend,
        progress: Option<&ProgressBar>,
    ) -> Result<CloudapBuildStats> {
        if iterations == 0 {
            bail!("CloudAP iteration count must be non-zero");
        }
        let backend = resolve_backend(backend)?;
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
            return build_empty_cache(dictionary_path, output_path, iterations, backend, fresh);
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
            let chunks = match backend {
                CloudapBuildBackend::Cpu => std::thread::scope(|scope| {
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
                }),
                CloudapBuildBackend::Cuda => {
                    vec![process_cuda_ranges(data, &ranges, iterations)?]
                }
                CloudapBuildBackend::Auto => unreachable!("backend is resolved before building"),
            };

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
            backend,
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

    /// Scan prederived keys against one CloudAP target using all available CPU
    /// threads. `limit == 0` returns every match; otherwise the earliest matches
    /// in cache order are returned.
    pub fn scan(
        &self,
        target: &CloudapTarget,
        limit: usize,
        progress: Option<&ProgressBar>,
    ) -> Result<Vec<CloudapMatch>> {
        self.scan_with_threads(target, limit, 0, progress)
    }

    /// Scan with an explicit worker count. `threads == 0` uses all available
    /// logical CPUs. Work is handed out in bounded, ascending chunks so a
    /// first-match scan can stop outstanding workers without changing which
    /// duplicate would have been returned by the former sequential scan.
    pub fn scan_with_threads(
        &self,
        target: &CloudapTarget,
        limit: usize,
        threads: usize,
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
        if record_count == 0 {
            return Ok(Vec::new());
        }

        let requested_threads = if threads == 0 {
            std::thread::available_parallelism()
                .map(|value| value.get())
                .unwrap_or(1)
        } else {
            threads.max(1)
        };
        let worker_count = requested_threads.min(record_count);
        let next_chunk = AtomicUsize::new(0);
        let best_match = AtomicUsize::new(usize::MAX);

        let mut indexed_matches = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..worker_count)
                .map(|_| {
                    scope.spawn(|| {
                        let mut local_matches = Vec::new();
                        loop {
                            let start = next_chunk.fetch_add(SCAN_CHUNK_RECORDS, Ordering::Relaxed);
                            if start >= record_count
                                || (limit == 1
                                    && start >= best_match.load(Ordering::Relaxed))
                            {
                                break;
                            }
                            let end = (start + SCAN_CHUNK_RECORDS).min(record_count);
                            let mut scanned = 0u64;
                            for index in start..end {
                                if limit == 1 && index >= best_match.load(Ordering::Relaxed) {
                                    break;
                                }
                                let record_start = index * RECORD_SIZE;
                                let record =
                                    &records[record_start..record_start + RECORD_SIZE];
                                scanned += 1;
                                if target.verify_derived_key_bytes(&record[..KEY_SIZE]) {
                                    let offset = decode_offset(
                                        &record[KEY_SIZE..KEY_SIZE + OFFSET_SIZE],
                                    );
                                    local_matches.push((index, offset));
                                    if limit == 1 {
                                        best_match.fetch_min(index, Ordering::Relaxed);
                                        break;
                                    }
                                }
                            }
                            if let Some(pb) = progress {
                                pb.inc(scanned);
                            }
                        }
                        local_matches
                    })
                })
                .collect();
            handles
                .into_iter()
                .flat_map(|handle| {
                    handle
                        .join()
                        .expect("CloudAP scan worker panicked")
                })
                .collect::<Vec<_>>()
        });
        indexed_matches.sort_unstable_by_key(|&(index, _)| index);
        if limit != 0 {
            indexed_matches.truncate(limit);
        } else if let Some(pb) = progress {
            pb.set_position(self.header.record_count);
        }

        let dictionary = self.dictionary_mmap.as_deref();
        let mut matches = Vec::with_capacity(indexed_matches.len());
        for (_, offset) in indexed_matches {
            let dictionary = dictionary
                .context("CloudAP cache matched a key but its dictionary is empty")?;
            matches.push(CloudapMatch {
                dictionary_offset: offset,
                plaintext: dictionary_word(dictionary, offset)?,
            });
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

fn resolve_backend(requested: CloudapBuildBackend) -> Result<CloudapBuildBackend> {
    match requested {
        CloudapBuildBackend::Cpu => Ok(CloudapBuildBackend::Cpu),
        CloudapBuildBackend::Auto => Ok(if cuda_device_count().unwrap_or(0) > 0 {
            CloudapBuildBackend::Cuda
        } else {
            CloudapBuildBackend::Cpu
        }),
        CloudapBuildBackend::Cuda => {
            if !cloudap_cuda_compiled() {
                bail!(
                    "CUDA support is not present in this binary; rebuild Preimage on a host with nvcc in PATH"
                );
            }
            if cuda_device_count()? == 0 {
                bail!("CUDA was requested but no CUDA device is available");
            }
            Ok(CloudapBuildBackend::Cuda)
        }
    }
}

#[derive(Default)]
struct PreparedCudaChunk {
    key_blocks: Vec<u8>,
    offsets: Vec<u64>,
    invalid_utf8_lines: u64,
}

fn process_cuda_ranges(
    data: &[u8],
    ranges: &[(usize, usize)],
    iterations: u32,
) -> Result<ProcessedChunk> {
    let prepared = std::thread::scope(|scope| {
        let handles: Vec<_> = ranges
            .iter()
            .map(|&(start, end)| scope.spawn(move || prepare_cuda_range(data, start, end)))
            .collect();
        handles
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .expect("CloudAP CUDA preparation worker panicked")
            })
            .collect::<Vec<_>>()
    });
    let record_count: usize = prepared.iter().map(|chunk| chunk.offsets.len()).sum();
    let mut key_blocks = Vec::with_capacity(record_count * 64);
    let mut offsets = Vec::with_capacity(record_count);
    let mut invalid_utf8_lines = 0;
    for chunk in prepared {
        key_blocks.extend_from_slice(&chunk.key_blocks);
        offsets.extend_from_slice(&chunk.offsets);
        invalid_utf8_lines += chunk.invalid_utf8_lines;
    }
    if offsets.is_empty() {
        return Ok(ProcessedChunk {
            invalid_utf8_lines,
            ..ProcessedChunk::default()
        });
    }
    let device_count = cuda_device_count()?;
    let derived = cuda_pbkdf2_multi(&key_blocks, offsets.len(), iterations, device_count)?;
    let mut bytes = Vec::with_capacity(offsets.len() * RECORD_SIZE);
    for (index, offset) in offsets.into_iter().enumerate() {
        bytes.extend_from_slice(&derived[index * KEY_SIZE..(index + 1) * KEY_SIZE]);
        encode_offset(offset, &mut bytes);
    }
    Ok(ProcessedChunk {
        bytes,
        records: record_count as u64,
        invalid_utf8_lines,
    })
}

fn prepare_cuda_range(data: &[u8], start: usize, end: usize) -> PreparedCudaChunk {
    let mut result = PreparedCudaChunk::default();
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
                let mut key_block = [0u8; 64];
                if utf16.len() <= key_block.len() {
                    key_block[..utf16.len()].copy_from_slice(&utf16);
                } else {
                    key_block[..32].copy_from_slice(&Sha256::digest(&utf16));
                }
                result.key_blocks.extend_from_slice(&key_block);
                result.offsets.push(pos as u64);
            }
            Err(_) => result.invalid_utf8_lines += 1,
        }
        pos = next;
    }
    result
}

#[cfg(preimage_cuda)]
fn cuda_device_count() -> Result<usize> {
    use std::ffi::CStr;
    use std::os::raw::{c_char, c_int};

    unsafe extern "C" {
        fn preimage_cuda_device_count(
            count: *mut c_int,
            error: *mut c_char,
            error_len: usize,
        ) -> c_int;
    }
    let mut count = 0;
    let mut error = [0i8; 512];
    let status = unsafe { preimage_cuda_device_count(&mut count, error.as_mut_ptr(), error.len()) };
    if status != 0 {
        let message = unsafe { CStr::from_ptr(error.as_ptr()) }.to_string_lossy();
        bail!("CUDA device query failed: {message}");
    }
    Ok(count.max(0) as usize)
}

#[cfg(not(preimage_cuda))]
fn cuda_device_count() -> Result<usize> {
    Ok(0)
}

#[cfg(preimage_cuda)]
fn cuda_pbkdf2_multi(
    key_blocks: &[u8],
    count: usize,
    iterations: u32,
    device_count: usize,
) -> Result<Vec<u8>> {
    if key_blocks.len() != count * 64 {
        bail!("internal CUDA key-block length mismatch");
    }
    if count == 0 {
        return Ok(Vec::new());
    }
    if device_count == 0 {
        bail!("CUDA PBKDF2 requested with no CUDA devices available");
    }

    let workers = device_count.min(count);
    let base = count / workers;
    let remainder = count % workers;
    let chunks = std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        let mut start = 0usize;
        for device in 0..workers {
            let chunk_count = base + usize::from(device < remainder);
            let end = start + chunk_count;
            let keys = &key_blocks[start * 64..end * 64];
            handles.push((
                start,
                end,
                scope.spawn(move || cuda_pbkdf2_on_device(keys, chunk_count, iterations, device)),
            ));
            start = end;
        }

        handles
            .into_iter()
            .map(|(start, end, handle)| {
                let output = handle
                    .join()
                    .expect("CloudAP CUDA device worker panicked")?;
                Ok((start, end, output))
            })
            .collect::<Result<Vec<_>>>()
    })?;

    let mut output = Vec::with_capacity(count * KEY_SIZE);
    for (start, end, chunk) in chunks {
        let expected = (end - start) * KEY_SIZE;
        if chunk.len() != expected {
            bail!(
                "CUDA device returned {} bytes for records {start}..{end}; expected {expected}",
                chunk.len()
            );
        }
        output.extend_from_slice(&chunk);
    }
    Ok(output)
}

#[cfg(preimage_cuda)]
fn cuda_pbkdf2_on_device(
    key_blocks: &[u8],
    count: usize,
    iterations: u32,
    device: usize,
) -> Result<Vec<u8>> {
    use std::ffi::CStr;
    use std::os::raw::{c_char, c_int};

    unsafe extern "C" {
        fn preimage_cloudap_pbkdf2(
            keys: *const u8,
            count: u64,
            iterations: u32,
            device: c_int,
            outputs: *mut u8,
            error: *mut c_char,
            error_len: usize,
        ) -> c_int;
    }
    let device = c_int::try_from(device).context("CUDA device index does not fit c_int")?;
    let mut output = vec![0u8; count * KEY_SIZE];
    let mut error = [0i8; 512];
    let status = unsafe {
        preimage_cloudap_pbkdf2(
            key_blocks.as_ptr(),
            count as u64,
            iterations,
            device,
            output.as_mut_ptr(),
            error.as_mut_ptr(),
            error.len(),
        )
    };
    if status != 0 {
        let message = unsafe { CStr::from_ptr(error.as_ptr()) }.to_string_lossy();
        bail!("CUDA PBKDF2 failed on device {device}: {message}");
    }
    Ok(output)
}

#[cfg(not(preimage_cuda))]
fn cuda_pbkdf2_multi(
    _key_blocks: &[u8],
    _count: usize,
    _iterations: u32,
    _device_count: usize,
) -> Result<Vec<u8>> {
    bail!("CUDA support is not present in this binary")
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
    backend: CloudapBuildBackend,
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
        backend,
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

    fn derived_key(password: &str, iterations: u32) -> [u8; KEY_SIZE] {
        let mut utf16 = Vec::new();
        for unit in password.encode_utf16() {
            utf16.extend_from_slice(&unit.to_le_bytes());
        }
        let mut key = [0u8; KEY_SIZE];
        pbkdf2_hmac::<Sha256>(&utf16, b"", iterations, &mut key);
        key
    }

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
    fn parallel_scan_preserves_cache_order_and_limit() {
        let dir = tempdir().unwrap();
        let words = dir.path().join("words.txt");
        let cache = dir.path().join("cloudap33700.pim");
        let dictionary = b"CorrectHorse\nwrong\nCorrectHorse\n";
        std::fs::write(&words, dictionary).unwrap();

        let iterations = 8;
        let correct = derived_key("CorrectHorse", iterations);
        let wrong = derived_key("wrong", iterations);
        let second_correct_offset = b"CorrectHorse\nwrong\n".len() as u64;
        let record_count = SCAN_CHUNK_RECORDS * 2;
        let first_match = SCAN_CHUNK_RECORDS - 1;
        let second_match = SCAN_CHUNK_RECORDS;
        let header = Header {
            iterations,
            dictionary_len: dictionary.len() as u64,
            dictionary_sha256: Sha256::digest(dictionary).into(),
            record_count: record_count as u64,
        };
        let mut bytes = Vec::with_capacity(HEADER_SIZE + record_count * RECORD_SIZE);
        bytes.extend_from_slice(&header.encode());
        for index in 0..record_count {
            bytes.extend_from_slice(if index == first_match || index == second_match {
                &correct
            } else {
                &wrong
            });
            encode_offset(
                if index == second_match {
                    second_correct_offset
                } else {
                    0
                },
                &mut bytes,
            );
        }
        std::fs::write(&cache, bytes).unwrap();

        let opened = CloudapCache::open(&cache, &words).unwrap();
        let target = CloudapTarget::parse(&target_for("CorrectHorse", iterations)).unwrap();
        let first = opened.scan_with_threads(&target, 1, 4, None).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].dictionary_offset, 0);

        let all = opened.scan_with_threads(&target, 0, 4, None).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].dictionary_offset, 0);
        assert_eq!(all[1].dictionary_offset, second_correct_offset);
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

    #[test]
    fn backend_names_parse_and_display() {
        for (name, backend) in [
            ("auto", CloudapBuildBackend::Auto),
            ("cpu", CloudapBuildBackend::Cpu),
            ("cuda", CloudapBuildBackend::Cuda),
        ] {
            assert_eq!(name.parse::<CloudapBuildBackend>().unwrap(), backend);
            assert_eq!(backend.to_string(), name);
        }
        assert!("gpu".parse::<CloudapBuildBackend>().is_err());
    }

    #[test]
    #[cfg(not(preimage_cuda))]
    fn explicit_cuda_fails_closed_when_kernel_is_not_compiled() {
        let dir = tempdir().unwrap();
        let words = dir.path().join("words.txt");
        let cache = dir.path().join("cloudap33700.pim");
        std::fs::write(&words, b"password\n").unwrap();
        let error = CloudapCache::build_with_backend(
            &words,
            &cache,
            4,
            1,
            false,
            CloudapBuildBackend::Cuda,
            None,
        )
        .unwrap_err();
        assert!(error.to_string().contains("CUDA support is not present"));
        assert!(!cache.exists());
    }

    #[test]
    #[cfg(preimage_cuda)]
    fn cuda_backend_is_byte_identical_to_cpu_when_a_device_is_available() {
        if cloudap_cuda_device_count().unwrap_or(0) == 0 {
            return;
        }
        let dir = tempdir().unwrap();
        let words = dir.path().join("words.txt");
        let cpu_cache = dir.path().join("cpu.pim");
        let cuda_cache = dir.path().join("cuda.pim");
        std::fs::write(
            &words,
            "password\nCorrectHorse\nemoji-🔐\nthis password deliberately exceeds thirty-two UTF-16 code units\n",
        )
        .unwrap();
        CloudapCache::build_with_backend(
            &words,
            &cpu_cache,
            8,
            2,
            false,
            CloudapBuildBackend::Cpu,
            None,
        )
        .unwrap();
        CloudapCache::build_with_backend(
            &words,
            &cuda_cache,
            8,
            2,
            false,
            CloudapBuildBackend::Cuda,
            None,
        )
        .unwrap();
        assert_eq!(
            std::fs::read(cpu_cache).unwrap(),
            std::fs::read(cuda_cache).unwrap()
        );
    }
}
