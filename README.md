# preimage

Hash lookup tables for password cracking. Given a wordlist, `preimage` builds a
sorted index that maps hash prefixes back to positions in that wordlist, so
recovering the plaintext behind a hash is a binary search and a seek instead of a
scan.

This repository holds two crates:

| Crate | What it is |
| --- | --- |
| [`preimage`](preimage/) | Index building, sorting, and lookup, plus the `preimage` CLI |
| [`allthehashes`](allthehashes/) | 58 hash algorithms behind one `HashAlgorithm` trait |

It is a Rust port of [crackstation-hashdb](https://github.com/defuse/crackstation-hashdb),
the PHP/C code behind [crackstation.net](https://crackstation.net/), and it reads and
writes the same on-disk index format.

## This fork

This fork keeps the same on-disk index format and lookup path, but speeds up index
creation and replaces the seek-heavy out-of-core quicksort with an external merge
sort. It also adds whole-folder ingest to `create`.

### Measured performance

The figures below are from release builds of upstream commit `066dce2` and this
fork's performance code at `0df4d21`, run on the same Intel Core i5-14600T system
(20 logical CPUs, 32 GiB RAM, NVMe storage).

The larger benchmark corpus is 13 FrequencyWords 2018 language files concatenated
in a fixed order (`en,de,fr,es,it,pt,nl,pl,sv,no,da,cs,fi`): 15,386,951 lines /
206,759,414 bytes (about 197 MiB), SHA-256
`bc217863338a6f4bd033292a286a4eddf2e54378923c446d4b16334982947038`.
The resulting index is 215,417,314 bytes (about 205 MiB).

| workload | upstream | this fork | result |
| --- | ---: | ---: | ---: |
| `create` MD5 | 2.663 s | **0.598 s** | **4.46× faster** |
| `create` NTLM | 2.522 s | **0.492 s** | **5.13× faster** |
| sort, 2 GiB budget | 1.202 s | 1.240 s | effectively unchanged |
| sort, 128 MiB budget | 66.212 s | **2.074 s** | **31.9× faster** |
| sort, 64 MiB budget | 83.599 s | **1.808 s** | **46.2× faster** |
| 4-hash lookup batch | 3.459 ms | 3.499 ms | effectively unchanged |

`create` results are medians of five alternating runs per algorithm. The 2 GiB sort
result is the median of five alternating runs; the 128 MiB result is the median of
two alternating runs; the 64 MiB result is the median of three runs. Lookup is the
median of 20 alternating runs using three known hits (from the beginning, middle,
and end of the corpus) plus one guaranteed miss.

A separate real-world run on an approximately 15 GB dictionary was observed to drop
from about 3 hours with upstream to about 6 minutes with this fork (roughly 30×).
That field result is included as a scale datapoint, not as part of the controlled
benchmark above.

The sort numbers need context: when the whole index fits the configured memory
budget, both versions sort in memory and performance is essentially the same. The
large improvement appears when the index exceeds that budget. Upstream then performs
file-based quicksort with per-entry seeks; this fork generates sorted runs and k-way
merges them using sequential I/O. The external merge needs scratch space roughly the
size of the index beside the index file.

For this corpus, MD5 and NTLM indexes produced by both versions were byte-for-byte
identical before sorting, the sorted MD5 indexes were also byte-for-byte identical,
and the tested lookups returned identical results.

- **Parallel indexing.** `create` memory-maps the wordlist and parses and hashes
  line-aligned windows across the available CPUs while preserving deterministic
  output order.
- **External-merge sort.** Oversized indexes are sorted as bounded in-memory runs
  and merged with sequential I/O rather than seek-heavy file quicksort.
- **Folder ingest.** `create --dir <folder>` supports `--mode combined` (one
  concatenated dictionary/index) and `--mode separate` (one index per file plus a
  generated `tables.toml`). Separate mode validates all intended outputs before
  writing so an index or config cannot overwrite another input/output.
- **CloudAP/33700 KDF cache.** `preimage cloudap` can precompute the unsalted
  PBKDF2-HMAC-SHA256 work used by Windows CloudAP / Hashcat mode 33700 once per
  dictionary candidate, then reuse those derived keys against future CacheData
  targets. Folder builds are per-wordlist, resumable, and incremental; completed
  caches are skipped on restart.
- **Lookup is unchanged.** No normal hash lookup code was modified; measured lookup
  performance is flat within process/filesystem noise.

Install this fork's CLI with:

```bash
cargo install --git https://github.com/briangillan/preimage preimage
```

## How it works

A wordlist is arbitrary bytes separated by `\n`. For each word, `preimage` records a
14-byte index entry:

```text
+---------------------------+-------------------+
| first 8 bytes of the hash | 6-byte position   |
+---------------------------+-------------------+
```

The index is then sorted by hash prefix. To look a hash up, binary search the index
for its first 8 bytes, seek to each matching position in the wordlist, and read the
word. Because only a prefix is stored, a hit is a *candidate*: the word is re-hashed
to confirm it. That re-hash is also what distinguishes a full match from a prefix
match when you only have a truncated hash.

Storing a prefix rather than the whole digest is what keeps the index small and the
format algorithm-independent — a 14-byte entry costs the same whether it indexes MD5
or SHA-512.

The cost is one binary search over an mmap'd file. CrackStation's real wordlist is
about 1.2 billion words, which is roughly a 17 GB index and about 31 seeks per
lookup.

## Install

```bash
cargo install preimage                              # the CLI
cargo add preimage --no-default-features            # the library
```

The default features build the CLI, so a plain `cargo add preimage` also pulls
`clap`, `toml` and `serde` — 68 crates rather than 39. None of them is used by
the library; they exist only for `src/bin`. Turning them off costs a library
consumer nothing:

```toml
preimage = { version = "0.1", default-features = false }
```

`cargo install preimage` needs the defaults, which is why they are on. Cargo has
no way to default differently per target.

## Command line

```bash
# 1. Create an unsorted index from a wordlist
preimage create -a md5 -w wordlist.txt -o md5.idx

# 2. Sort it in place — DO NOT INTERRUPT, a partial sort corrupts the file
preimage sort md5.idx                 # 2 GiB buffer by default
preimage sort --memory 4G md5.idx     # bigger buffer, fewer passes
preimage sort --ram md5.idx           # all in RAM, errors if it doesn't fit

# 3. Confirm it is sorted
preimage check md5.idx

# 4. Look hashes up
preimage lookup -a md5 -i md5.idx -d wordlist.txt 5f4dcc3b5aa765d61d8327deb882cf99

# 5. See the supported algorithms
preimage list
```text

Sorting is deterministic: the same wordlist always produces a byte-identical index.

Sorting an index larger than the memory budget needs free disk space for a scratch
file about the size of the index, alongside it, which is renamed over the original
when the sort finishes. An index that fits in the budget is sorted in place with no
scratch file. As the warning says, do not interrupt a sort: the run-generation pass
rewrites the file in place, so an interrupted or failed sort (out of disk, for
instance) can leave it partially sorted and in need of a rebuild.

### Indexing a folder

`create --dir <folder>` indexes every file in a folder (sorted by name, for a
reproducible result) in one command. Two modes, because a lookup is a binary
search over one index — searching *N* separate indexes costs *N* of them:

```bash
# Combined: concatenate the folder into one dictionary and build one index over
# it. One binary search per lookup; rebuild the whole thing to add a file.
preimage create -a md5 --dir words/ --mode combined -o all.idx --dict all.txt
preimage sort all.idx
preimage lookup -a md5 -i all.idx -d all.txt <hash>

# Separate: one index per file, plus a generated config. Lookups search every
# table; add a file later without rebuilding the others.
preimage create -a md5 --dir words/ --mode separate --out-dir idx/ --config tables.toml
# sort each idx/*.idx, then:
preimage lookup --config tables.toml <hash>
```

Prefer `combined` unless the set of wordlists changes often: one index is the
fastest to search and matches the single-dictionary format. `combined` writes a
concatenated dictionary (with a newline inserted between files so words never
merge) that becomes the dictionary the positions point into, so keep it.

To search several tables at once, describe them in a config file and use
`preimage lookup --config tables.toml <hash>...` — this is also what
`--mode separate` writes for you:

```toml
[[table]]
label = "md5-small"
algorithm = "md5"
index = "/data/md5-small.idx"
dictionary = "/data/small.txt"

[[table]]
label = "sha1-small"
algorithm = "sha1"
index = "/data/sha1-small.idx"
dictionary = "/data/small.txt"
```

## CloudAP / Hashcat mode 33700 acceleration

Windows CloudAP CacheData mode 33700 is different from an ordinary hash lookup.
Current targets derive a 32-byte AES key as:

```text
PBKDF2-HMAC-SHA256(UTF-16LE(password), salt="", iterations=10000, dkLen=32)
```

There is no per-target salt, so the expensive PBKDF2 result for a candidate is
reusable across CloudAP targets. The target does **not** expose that derived key,
so it cannot use Preimage's normal sorted/binary-search index. Instead,
`preimage cloudap` stores fixed 38-byte records containing the 32-byte derived key
plus a 48-bit byte offset into the original dictionary. A target scan streams
those records and performs only the inexpensive target-specific AES marker check.
The dictionary is consulted only after a key matches.

Each completed cache is strongly bound to the exact dictionary by size and full
SHA-256. The build writes `<cache>.part` and flushes progress in bounded windows;
if interrupted, rerunning the same command repairs any incomplete final record and
resumes from the last completed candidate. No sort step is required.

### Build one dictionary

```bash
preimage cloudap build \
  --wordlist words.txt \
  --output words.cloudap33700.pim
```

`--threads 0` (the default) uses every available logical CPU. `--fresh` discards
both an existing completed cache and any resumable partial build.

If `nvcc` is in `PATH` when Preimage is compiled, the build automatically includes
the CUDA PBKDF2 kernel. `--backend auto` (the default) then uses an available NVIDIA
GPU and falls back to the parallel CPU implementation when CUDA is not compiled in
or no device is present. Use `--backend cpu` for a reproducible CPU-only run, or
`--backend cuda` to require a GPU and fail instead of falling back:

```bash
cargo build --release
preimage cloudap build \
  --backend cuda \
  --wordlist words.txt \
  --output words.cloudap33700.pim
```

The CPU and CUDA builders write the same version-1 cache records. CUDA accelerates
the 10,000-round PBKDF2 build; it does not materially help the later cache scan,
which streams already-derived keys and is normally limited by memory/storage I/O.

On an RTX 3070, a sustained 262,144-candidate CUDA validation batch measured
133.5 k candidates/s. Hashcat 7.1.2 mode 33700 measured 134.5 kH/s on the same host
(`Accel:2 Loops:500 Thr:512 Vec:1`). The GPU-produced cache was byte-identical to
the CPU-produced cache, including Unicode and long-password test cases. At that
rate, the 15.4-million-line benchmark corpus described above spends roughly two
minutes in the KDF; actual ingest also includes dictionary hashing and cache I/O.

### Build a folder incrementally

For the work-server layout used by this fork:

```bash
preimage cloudap build \
  --dir /media/raid/wordlists \
  --out-dir /media/raid/wordlists/pre/cloudap33700 \
  --config /media/raid/wordlists/pre/cloudap33700.toml
```

Each regular file directly inside `/media/raid/wordlists` receives its own cache.
If the command is restarted, valid completed caches are checked and skipped and the
current `.part` cache resumes. Keeping the caches separate avoids duplicating the
wordlists into another giant combined dictionary and makes adding a new wordlist
incremental.

The on-disk cost is 38 bytes per valid UTF-8 candidate plus a 64-byte header. For
example, one billion candidates require about 38 GB (35.4 GiB) of cache data.
Lines that are not valid UTF-8 are skipped and counted because the CloudAP KDF is
defined here over the Unicode password encoded as UTF-16LE.

### Scan a Spectre 33700 target

Single cache:

```bash
preimage cloudap scan \
  --cache words.cloudap33700.pim \
  --dictionary words.txt \
  '$MSONLINEACCOUNT$0$10000$...'
```

Folder config, using Spectre's exported `.hash` file directly:

```bash
preimage cloudap scan \
  --config /media/raid/wordlists/pre/cloudap33700.toml \
  --target-file cloudap-33700.hash
```

`--target-file` requires exactly one non-empty 33700 target. You can alternatively
pass the `$MSONLINEACCOUNT$0$...` target as a single-quoted positional argument.
The scan stops at the first match by default; add `--all` to report duplicates
across all configured dictionaries. Validate a cache/dictionary pair without
scanning a target with:

```bash
preimage cloudap check --cache words.cloudap33700.pim --dictionary words.txt
```

The cache does not contain plaintext passwords, but it contains reusable derived
key material that substantially reduces the work required to test its dictionary
against compatible CloudAP targets. Treat it as sensitive cracking material and
keep it with the protected wordlist/index store.

## Library

```toml
[dependencies]
preimage = { version = "0.1", default-features = false }
```

Everything below works with the default features off — they only add the CLI. See
[Install](#install) for what that saves, and [Trust](#trust) for what the library
requires of the files you point it at.

`PreimageOracle` is the multi-table entry point. Registration order is match order.

```rust,no_run
use preimage::{HashResult, PreimageOracle, MD5, SHA1};
use std::path::Path;

# fn main() -> anyhow::Result<()> {
let mut oracle = PreimageOracle::new();
oracle.register("md5", MD5, Path::new("md5.idx"), Path::new("wordlist.txt"))?;
oracle.register("sha1", SHA1, Path::new("sha1.idx"), Path::new("wordlist.txt"))?;

for result in oracle.crack(&["5f4dcc3b5aa765d61d8327deb882cf99"], false)? {
    match result {
        HashResult::Lookup { queried_hash, matches, .. } => {
            for m in matches {
                println!(
                    "{} = {:?} via {} ({}, full match: {})",
                    queried_hash,
                    m.lookup_match.plaintext_lossy(),
                    m.table_label,
                    m.lookup_match.algorithm().name(),
                    m.lookup_match.is_full(),
                );
            }
        }
        HashResult::InvalidFormat { input } => {
            println!("{input} is not a valid hash");
        }
    }
}
# Ok(())
# }
```

Invalid input is a variant, not an error: `crack` returns `InvalidFormat` for
non-hex, odd-length, or too-short input, and reserves `Err` for genuine I/O
failures. A hash that is well-formed but absent comes back as `Lookup` with an
empty `matches`.

You can index and crack with your own algorithm by implementing one trait:

```rust,no_run
use preimage::{HashAlgorithm, IndexFile, PreimageOracle};
use std::path::Path;

/// A toy algorithm, to keep the example self-contained: a real one would call
/// into a hash crate here and return the digest bytes.
struct MyHash;

impl HashAlgorithm for MyHash {
    fn hash(&self, input: &[u8]) -> Option<Vec<u8>> {
        let mut digest = [0u8; 8];
        for (slot, byte) in digest.iter_mut().zip(input) {
            *slot = *byte;
        }
        Some(digest.to_vec())
    }

    fn name(&self) -> &str {
        "my-hash"
    }
}

# fn main() -> anyhow::Result<()> {
let wordlist = Path::new("wordlist.txt");
let index_path = Path::new("my-hash.idx");
let mut oracle = PreimageOracle::new();

// Building takes any reference...
IndexFile::build(&MyHash, wordlist, index_path, None)?;

// ...while looking up stores the algorithm, so it wants a 'static one.
static MY_HASH: &dyn HashAlgorithm = &MyHash;
oracle.register("my-hash", MY_HASH, index_path, wordlist)?;
# Ok(())
# }
```

A custom algorithm does not join any registry: `preimage list` and the `-a` flag
resolve names through `allthehashes::get_algorithm`, which knows the built-ins
only. Your type works through the library, not the CLI.

Returning `None` marks input this algorithm cannot represent, and such words are
absent from the index rather than silently indexed as something else. NTLM is the
only shipped algorithm that uses it: it returns `None` for input that is not valid
UTF-8, matching the reference implementation's `iconv` failing. Every other
algorithm here, LM included, accepts any byte string.

## Trust

The index and dictionary files must be **trusted**, and must not change while a
`LookupTable` holds them open. `preimage` searches data you built and own; it is not
hardened against a hostile index or wordlist.

A corrupt, truncated, unsorted or mismatched pair can make it return confidently wrong
answers, or terminate the process — an unsorted index defeats the binary search, and a
dictionary with no line terminator makes a lookup allocate until the allocator gives up.
Sortedness is not checked at open, deliberately: a production index is hundreds of
gigabytes and verifying it would mean reading all of it. `preimage check` does that when
you want it.

What malformed files cannot do is read out of bounds. The entry count comes from the
file's own length and every access is a bounds-checked slice, so a bad index panics
rather than reading past the mapping.

Note this is a claim about *files*. The robustness claim below — that invalid input is a
variant rather than an error — is about the **query string**, and does not extend to the
files.

## Compatibility

`preimage` reads indexes built by the original `createidx.php`. The test suite cracks
hashes against committed PHP-generated fixtures for md5, sha1 and NTLM, and checks a
PHP-sorted index with `preimage`'s own checker, rather than trusting the format
description.

The other direction — the original `checksort` accepting an index `preimage` wrote — is
not tested here, because that tool is not part of this repository.

## Development

```bash
cargo test                 # the two libraries
cargo test --all-features  # everything, including the CLI and benchmark binaries
```

Both binaries are behind features — `preimage` behind `cli`, `benchmark` behind
`bench` — so a plain `cargo test` does not compile them and silently skips their
tests. Use `--all-features` to run the whole suite.

Sorting is covered at the buffer-capacity boundaries — exactly at capacity, one
under, one over, and multiples of it — plus already-sorted, reverse-sorted and
all-identical inputs. Every case runs at three memory budgets, so each one is
sorted both entirely in memory and through the external merge sort, and the two
are required to produce byte-identical files.

The out-of-core path is an external merge sort: one pass writes budget-sized
sorted runs back over the file, then a k-way merge streams them into a scratch
file next to the index and renames it over the original (in more than one merge
pass only when there are more runs than the merge fan-in). Both phases are
sequential I/O, and the cost is the same `O(n log n)` on every input — there is
no adversarial case, because the byte-identical requirement is what pins the
order down and the comparator is a total order (hash prefix, then the unique
wordlist position), so all-identical prefixes are just an ordinary run of
distinct keys. The trade for dropping the old in-place quicksort's per-entry
seeking is that scratch file: the merge needs free space about the size of the
index.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual
licensed as above, without any additional terms or conditions.

## AI Use Policy

This software was written with heavy assistance from AI tools, and **has not yet
been reviewed by a human**. I intend to review it and will update this notice once I
have.

If you would like to submit a PR, using AI is fine, but you must stand by the
correctness of your submission as strongly as you would if you had written the code
yourself.
