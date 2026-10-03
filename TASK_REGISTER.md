# Preimage Task Register

Updated: 2026-10-02

## Goal

Reduce the deployed Preimage dataset from the current ~702.43 GiB footprint to below 500 GB if practical, while preserving all 11,901,699,218 deduplicated password candidates and keeping NTLM and MSOnline/CloudAP lookup throughput at or near current performance.

## Production Dataset Baseline

| File | Purpose | Bytes | Approx. GiB |
|---|---|---:|---:|
| `bigdict.txt` | Deduplicated password dictionary | 136,291,884,307 | 126.93 |
| `bigdictsntlm.idx` | NTLM sorted prefix index | 166,366,525,626 | 154.94 |
| `bigdict.msonline.pim` | MSOnline/CloudAP precomputed cache | 451,566,283,906 | 420.56 |
| **Total** |  | **754,224,693,839** | **702.43** |

Dictionary candidate count: **11,901,699,218 passwords**

Observed Windows NTFS LZX results:
- PIM completed at about **1.1:1** compression.
- Dictionary completed at about **5:1** compression.
- Full dataset completed at about **1.4:1**, occupying **550,005,972,992 bytes (~512.24 GiB)** on disk.
- Total allocated-space saving versus the 754,224,693,839-byte logical dataset: **204,218,720,847 bytes (~204.22 GB, ~27.1%)**.
- The Windows deployment is now only **50,005,972,992 bytes (~50.01 GB decimal)** above the <500 GB target.

Current format facts:
- NTLM IDX entry: 8-byte hash prefix + 6-byte dictionary byte offset = **14 bytes**.
- CloudAP PIM record: 32-byte derived key + 6-byte dictionary byte offset = **38 bytes**.

Current performance reference:
- Full ~451.6 GB PIM scan on Comino is approximately **2 minutes**.
- Effective scan/read rate is roughly **3.8 GB/s**.
- This is a key performance gate.

## Priority 0 — Baselines and compatibility

### PRE-001: Record reproducible baseline metrics
Status: PARTIAL
Difficulty: Easy

Record current-format:
- NTLM known-hit lookup time.
- NTLM known-miss lookup time.
- CloudAP/MSOnline known-hit scan time.
- CloudAP/MSOnline known-miss scan time.
- `preimage check` times.
- File sizes and hashes.
- CPU and storage throughput where useful.
- revision/build configuration, filesystem/device, cache state and repeated elapsed-time results.
- dictionary entry count, IDX entry count and PIM record count using explicit counting definitions.
- provenance/input identity for the dictionary, IDX and PIM.
- invalid-UTF-8 skip accounting, including whether the source figure covers a fresh full build or only the current invocation after resume.

Known arithmetic reconciliation:
- Dictionary entries: **11,901,699,218**.
- IDX entries: `166,366,525,626 / 14` = **11,883,323,259** exactly.
- PIM records: `(451,566,283,906 - 64) / 38` = **11,883,323,259** exactly.
- Difference from dictionary: **18,375,959**.

Current source strongly suggests the excluded CloudAP entries are invalid-UTF-8 lines, but this must be confirmed with whole-input accounting. A completion log from a resumed build is not sufficient because the invalid-UTF8 counter is invocation-local while the record count may include resumed records.

Progress:
- Canonical production figures and count reconciliation are recorded in `DATASET.md`.
- Workspace baseline on checkout `184bb9e`: `cargo test --workspace --all-targets` passed **387 tests** with zero failures on 2026-10-02.
- Production artifact hashes, whole-input invalid-UTF8 accounting and reproducible Comino timing conditions remain outstanding.

Acceptance:
- Results documented before v2 format changes land.
- Every count has a source, scope and counting definition.
- Performance comparisons use equivalent conditions and an explicit allowed regression threshold.

### PRE-002: Add explicit v1 compatibility tests
Status: DONE
Difficulty: Easy

Inventory and extend the existing compatibility evidence rather than duplicating it. Existing coverage includes legacy PHP-generated reference indexes, malformed/empty-entry handling, PIM dictionary binding, invalid-UTF8 handling, partial-build/torn-record handling and a conditional CPU/CUDA byte-identity test.

Add immutable old-format fixtures where needed so compatibility is not tested only by a current-writer/current-reader round trip. Record whether hardware-dependent CUDA checks actually executed.

Completed:
- Existing committed PHP-generated IDX fixtures remain the immutable legacy IDX compatibility evidence.
- Added a writer-independent, manually assembled PIM v1 fixture test that opens and cracks a known candidate without using the current PIM writer/header encoder.
- Hardware-dependent CUDA byte-identity evidence remains tracked under PRE-012 because execution requires CUDA hardware.

Acceptance:
- Existing v1 files continue to open/search/check.
- Tests fail if backward compatibility is removed.
- Fixture provenance and hardware-dependent execution evidence are documented.

## Priority 1 — CloudAP PIM v2

### PRE-010: Define PIM v2 with 32-byte records
Status: DONE
Difficulty: Easy–Moderate

Current PIM v1:
- 32-byte derived key
- 6-byte dictionary offset

PIM v2 implemented:
- version **2** in the existing 64-byte PIM header
- 32-byte derived key only
- accepted-candidate ordinal implied by record number
- v1/version 1 remains fully readable

The current PIM file length is exactly consistent with **11,883,323,259 v1 records** after its 64-byte header: `(451,566,283,906 - 64) / 38`.

That is **18,375,959 fewer PIM records than dictionary lines**. The current code path indicates invalid UTF-8 dictionary lines are skipped while empty valid-UTF8 lines are retained, so the working hypothesis is that this delta is the invalid-UTF8 set. Confirm this with whole-input accounting before relying on it. V2 must define ordinals over the accepted CloudAP candidate stream, not raw dictionary line number.

At the production record count, PIM v2 size is projected as:
- cache: **380,266,344,352 bytes including the 64-byte header**
- ordinal sidecar (65,536-candidate stride): **2,901,280 bytes (~2.77 MiB)**
- combined: **380,269,245,632 bytes**
- cache alone: **354.15 GiB**

Expected saving versus current PIM:
- **71,299,939,554 bytes (~71.30 GB decimal)**
- ~15.8%

Requirements:
- Keep v1 reader support.
- Add explicit v2 versioning.
- Builder/checker/search understand both formats.
- Search hot path works directly on 32-byte records.

Acceptance:
- Same candidate coverage.
- Same hit/miss answers.
- No material scan slowdown; faster is expected on storage-bound systems.

### PRE-011: Candidate ordinal to plaintext lookup
Status: DONE
Difficulty: Moderate

Implement a shared dictionary ordinal lookup so PIM v2 can map accepted-candidate ordinal N to the correct dictionary plaintext without storing a 6-byte offset in every record.

Preferred first implementation:
- sparse checkpoints keyed by **PIM record ordinal**, not raw line number
- each checkpoint stores the corresponding dictionary byte offset
- resolve candidate N by seeking to the nearest checkpoint and scanning forward while skipping invalid-UTF8 lines until ordinal N is reached

Implemented sidecar:
- sibling path: `<cache>.ord`
- 64-byte header binding stride, dictionary length, SHA-256 and accepted-candidate count
- 16-byte checkpoints: accepted-candidate ordinal + dictionary byte offset
- default stride: **65,536 accepted candidates**
- invalid-UTF8 lines are skipped during forward resolution
- existing matching sidecars are reused; dictionary mismatch causes rebuild/refusal as appropriate

The format is deliberately compatible with a future seekable compressed-dictionary block table.

Acceptance:
- Correct first/middle/last lookup.
- Correct final-line handling.
- Sidecar remains small relative to dictionary.
- This path is not used during full PIM scans.

### PRE-012: PIM v2 build/resume support
Status: IMPLEMENTED — CUDA hardware validation pending
Difficulty: Moderate

Adapt CPU and CUDA builders to emit v2 32-byte records.

Requirements:
- CPU and CUDA output byte-compatible, including passwords whose UTF-16 encoding exceeds 64 bytes.
- Resume/truncation aligned to 32-byte records.
- Resume uses the PRE-011 sparse accepted-candidate ordinal sidecar to recover the dictionary position; do not require an O(dictionary) scan on every resume.
- Cross-backend resume continues to work.
- Preserve progress/safety checks.
- Treat process interruption, disk-full/write failure, publication failure and power-loss durability as separate failure cases.

Completed evidence:
- CPU v2 fresh build works.
- v2 build/scan correctly crosses invalid-UTF8 dictionary lines.
- torn 32-byte partial records are repaired and resumed using the sidecar ordinal, not an embedded offset.
- `CloudapCache::open/check/search` handle both v1 and v2.
- CLI opt-in: `preimage cloudap build ... --compact-cache`.
- full workspace suite passes **399 tests, zero failures** after adding CLI v2 coverage.
- the existing conditional CUDA parity test now also compares v2 cache bytes and sidecar bytes, including a >64-byte UTF-16 HMAC key case.

Remaining hardware gate:
- execute the CUDA parity test on a CUDA-capable build/host; this checkout has no `nvcc`/CUDA runtime available.

### PRE-013: Benchmark PIM v2
Status: PARTIAL — Windows smoke benchmark complete; air-gapped Comino production benchmark pending
Difficulty: Easy

Compare v1 vs v2:
- file size
- full miss scan throughput
- hit scan throughput
- CPU usage
- storage throughput

Windows smoke evidence (2026-10-03, `windows-builder`, current source release build):
- 3-candidate `cloudap33700_words.txt` fixture built successfully as both v1 and compact v2.
- v1 cache: **178 bytes** = 64-byte header + 3 × 38-byte records.
- v2 cache: **160 bytes** = 64-byte header + 3 × 32-byte records.
- v2 ordinal sidecar: **80 bytes** for this tiny fixture; fixed metadata dominates at this scale and is negligible at production scale.
- both `cloudap check` operations passed with dictionary binding verified.
- five-process known-hit timings after first launch were approximately **6–7 ms** for both formats; this fixture is intentionally too small for throughput conclusions.
- full Windows `cargo test --workspace --all-targets` passed **398 tests** with zero failures (262 + 3 + 73 + 12 + 5 + 19 + 24).

This smoke benchmark validates the benchmark path and v1/v2 behavioural parity on Windows.

Debian CPU-only evidence (2026-10-03, current source, Rust/Cargo 1.99 release build in a clean target directory):
- generated a 100,001-candidate synthetic CloudAP dictionary and built both formats successfully with `backend=cpu (CUDA devices=0)`.
- v1 cache: **3,800,102 bytes**; v2 cache: **3,200,096 bytes** plus **96-byte** ordinal sidecar.
- raw cache reduction is exactly **600,006 bytes**, i.e. **6 bytes per candidate**; including the tiny sidecar the combined reduction is 599,910 bytes (~15.79%).
- CPU build wall time was **9.405 s v1** and **11.291 s v2** in single runs; this is not treated as a regression measurement because build-order/system noise was not controlled.
- five warm process-level known-hit and full-miss searches were approximately **7–12 ms v1** and **8–10 ms v2**. At a 3–4 MB cache size process/startup overhead dominates, but no material v2 scan penalty is visible.
- Linux release test suite passed **399 tests** with zero failures (262 + 3 + 74 + 12 + 5 + 19 + 24).

The Debian result confirms CPU-only v2 correctness, exact record-size reduction, sidecar operation, and scan parity on a moderate fixture. It does **not** satisfy the production performance gate: CPU usage, storage throughput, large full-miss throughput and the ~2-minute production baseline still require measurement on the air-gapped Comino dataset.

Target:
- ~15.8% raw reduction.
- no material slowdown.
- preserve approximately 2-minute Comino full-scan baseline or improve it.

## Priority 2 — Dictionary storage

### PRE-020: Measure real dictionary compression
Status: TODO
Difficulty: Easy

Take representative chunks from the real 136,291,884,307-byte `bigdict.txt`:
- beginning
- ~25%
- ~50%
- ~75%
- end

Test:
- zstd at practical runtime levels
- optionally LZ4 for speed comparison

Record:
- ratio
- compression speed
- decompression speed

### PRE-021: Seekable block-compressed dictionary prototype
Status: TODO
Difficulty: Moderate

Prototype a portable dictionary container with independently compressed blocks.

Suggested metadata per block:
- first ordinal
- candidate count
- compressed offset
- compressed length
- uncompressed length

Use zstd first. Add a small LRU cache for decompressed blocks.

Requirements:
- portable Windows/Linux
- candidate ordinal lookup decompresses only one relevant block
- full PIM/IDX scans do not decompress dictionary data unless there is a hit

### PRE-022: Complete Windows LZX measurements
Status: DONE
Difficulty: Easy

Record completed NTFS LZX ratios for:
- dictionary
- IDX
- PIM

Measured:
- PIM ≈ **1.1:1**
- Dictionary ≈ **5:1**
- Whole dataset ≈ **1.4:1**, **550,005,972,992 bytes** allocated

LZX is a SpectreDemo deployment optimisation only, not the canonical Preimage format.

## Priority 3 — NTLM index v2

### PRE-029: Easy IDX v2 — 5-byte dictionary offsets
Status: DONE
Difficulty: Easy–Moderate

The 136,291,884,307-byte dictionary's largest byte offset fits in 37 bits. A 5-byte/40-bit offset is therefore sufficient and reduces IDX entries from 14 to 13 bytes without changing sort order or lookup semantics.

Implemented layout:
- 24-byte explicit `PREIMAGE-IDX2` header
- 8-byte hash prefix + 5-byte dictionary byte offset = 13-byte entries
- CLI opt-in: `preimage create ... --compact-index`
- legacy headerless 14-byte v1 remains the default and fully readable

At 11,883,323,259 production IDX entries, projected IDX2 size is **154,483,202,391 bytes**, saving **11,883,323,235 bytes (~11.88 GB decimal)** after the 24-byte header.

Requirements:
- explicit IDX v2 versioning
- retain v1 14-byte reader support
- audit `ENTRY_SIZE`, `POSITION_LEN`, packed-layout assertions and unsafe bulk read/write code

Completed evidence:
- build/sort/check/mmap lookup round-trip passes against the known NTLM `apple` fixture
- targeted external-merge test proves the IDX2 header survives scratch-file ping-pong
- full workspace suite passes **392 tests, zero failures**

Acceptance:
- identical lookup answers to v1
- no material lookup regression
- size reduction matches the 1-byte-per-entry calculation

Remaining production gate:
- benchmark lookup/sort throughput on production-scale IDX2 before making it the default

### PRE-034: CUDA-accelerate NTLM/IDX generation
Status: DONE — CUDA hardware validation passed on Sumuri
Difficulty: Moderate

Use the existing optional CUDA build path to accelerate NTLM index generation automatically when CUDA devices are present. CPU remains the fallback; there is no required backend flag.

Implemented:
- host parsing retains exact dictionary byte offsets, two-sided CR/LF trimming and invalid-UTF8 rejection semantics.
- valid UTF-8 candidates are converted to UTF-16LE on the host and batched for GPU hashing.
- CUDA kernel implements arbitrary-length, multi-block MD4 and returns full 16-byte NTLM digests; the existing index writer stores the required 8-byte prefix in either legacy IDX v1 or compact IDX2.
- one line-aligned range is dispatched per visible CUDA device, so Comino's six GPUs can work concurrently while output is reassembled in dictionary order.
- empty passwords and inputs longer than one MD4 block are supported.
- `preimage create -a ntlm ...` auto-selects CUDA when compiled in and devices are visible, otherwise CPU, and reports the selected backend/device count.
- non-NTLM algorithms remain on the existing CPU builder.
- conditional CUDA test compares GPU entries byte-for-byte with CPU NTLM across ASCII, emoji, invalid UTF-8, empty and multi-block inputs.
- CPU-only regression suite passes **399 tests** with zero failures after implementation.

Hardware validation (Sumuri, 2026-10-03):
- NVIDIA GeForce RTX 3070, driver 580.173.02, CUDA Toolkit 13.0 (`nvcc` V13.0.88), Rust/Cargo 1.99.0.
- CUDA-required release build succeeded with `PREIMAGE_REQUIRE_CUDA=1`; the conditional CUDA parity test executed on device 0 and passed against CPU NTLM for ASCII, emoji/UTF-16, invalid UTF-8, empty and multi-block inputs.
- A deterministic 2,000,000-candidate / 48,000,000-byte dictionary produced byte-identical unsorted compact IDX2 output on CPU and CUDA. Both files had SHA-256 `94f3990dd586362cfaf86c8ea151af0069d1e58e1ca20999e90692955e7e6fdf`; `cmp` passed.
- Initial timings exposed a severe compact-IDX2 output bottleneck: 2M took CPU 3.25 s / CUDA 3.57 s; 50M took CPU 79.85 s / CUDA 85.62 s. IDX2 was issuing two tiny writes per entry.
- IDX2 output now batch-serializes compact entries and performs one bulk write per worker range. On the same 50M / 1.2 GB fixture CPU fell to **1.42 s (~35.2M candidates/s)** and CUDA to 7.70 s.
- CUDA now returns only the required 8-byte index prefix rather than the unused full 16-byte MD4 digest, cutting device output and D2H traffic; the RTX 3070 result improved to 6.90 s.
- CUDA host preparation is now CPU-parallel even when only one GPU is present; prepared ranges are round-robin dispatched across visible GPUs. RTX 3070 time improved again to **2.55 s (~19.6M candidates/s)**.
- Net improvement on the 50M fixture: CPU **56.2x faster** (79.85 -> 1.42 s); CUDA **33.6x faster** (85.62 -> 2.55 s). CPU and CUDA IDX2 output remains byte-identical with SHA-256 `6e8d3b16e9dcb04b9ac8b16cad84f6e5fb4db93385c1f932da1abb3b710bc2a9`.
- Sumuri's CPU remains ~1.8x faster than its single RTX 3070 for this very cheap NTLM workload. The six-GPU Comino test is therefore the meaningful remaining CUDA throughput/scaling gate.
- An initial parity run failed with CUDA OOM while the RTX 3070 had ~7.6/8 GiB VRAM occupied by other workloads. After freeing VRAM (5,961 MiB free), the same test passed. Production use should ensure sufficient free VRAM or add bounded batching/allocation handling if shared-GPU operation is required.

Remaining production-scale performance gate:
- benchmark the production-size NTLM build on Comino's six RTX 4090s before regenerating the 11.9-billion-candidate IDX2; record 1-GPU vs 6-GPU candidates/s and utilisation. This is a throughput/capacity gate, not a correctness gate for PRE-034.

### PRE-030: Remove per-entry dictionary byte offsets
Status: TODO
Difficulty: Hard / design required

Current entry:
- 8-byte sorted hash prefix
- 6-byte dictionary byte offset
- 14 bytes total

Constraint:
- 11,901,699,218 candidates require at least 34 bits for a unique ordinal.
- 32-bit IDs are insufficient.

Investigate:

A. Reorder canonical dictionary to match sorted NTLM index order so index position is candidate ordinal.

B. Keep dictionary order and store a compact ordinal mapping separately from the hot prefix structure.

Do not destructively reorder production data without migration and benchmark evidence.

### PRE-031: Evaluate succinct sorted-prefix representation
Status: TODO
Difficulty: Hard

Evaluate:
- Elias–Fano
- partitioned Elias–Fano
- blockwise delta coding
- another memory-map-friendly monotonic representation

Requirements:
- efficient lower-bound/range lookup
- duplicate/collision range support
- benchmark against current binary search

Goal:
- materially below 8 raw bytes/prefix
- lookup latency within a few percent of current implementation if practical

### PRE-032: Evaluate 56-bit NTLM prefixes
Status: TODO
Difficulty: Moderate–Hard

Assess 56-bit prefixes. Full NTLM candidate verification already exists in the lookup path, so this is primarily a space/performance and collision-block-size experiment rather than a new correctness mechanism.

Requirements:
- quantify actual collision-block size distribution on production-like data, including tail/worst-case behaviour
- preserve full-hash candidate verification before reporting success
- add 56-bit multi-entry collision tests
- confirm worst-case block walks remain effectively interactive

### PRE-033: NTLM v2 migration/compatibility
Status: TODO
Difficulty: Moderate

If v2 is adopted:
- keep v1 reader support
- explicit versioning
- safe rebuild/conversion path
- never replace a known-good v1 index until v2 validation passes
- failed migration must leave the previous validated generation usable

## Priority 4 — Integrated sub-500 GB target

### PRE-040: Build measured size model
Status: TODO
Difficulty: Easy

Use measured—not estimated—sizes for:
- PIM v2
- chosen NTLM v2 structure
- compressed dictionary
- sidecar/index metadata

Record separately:
- portable logical bytes
- deployed allocated bytes
- peak migration bytes including old generation, new generation, temporary files and rollback headroom

Target:
- complete portable dataset **<500,000,000,000 bytes** if practical
- document decimal GB and binary GiB together
- do not double-count filesystem-level compression/deduplication as portable-format savings

### PRE-041: End-to-end correctness test
Status: TODO
Difficulty: Moderate

Run:
- NTLM hit
- NTLM miss
- CloudAP hit
- CloudAP miss
- checks on all data files
- Windows
- Linux

Acceptance:
- same answers as current production data
- no candidate loss
- distinguish structural validity, dictionary identity, artifact integrity, completeness and behavioural compatibility; do not treat a single successful `check` as proving all of them

### PRE-042: End-to-end performance gate
Status: TODO
Difficulty: Moderate

Requirements:
- CloudAP full PIM scan must not materially regress from ~2 minutes on Comino.
- NTLM lookup remains effectively interactive.
- Dictionary decompression is off the hot scan path.
- USB-HDD deployments should benefit from reduced physical I/O.

### PRE-043: Dataset generation manifest
Status: TODO
Difficulty: Easy–Moderate

Create a small manifest for each complete dataset generation recording:
- artifact roles and format versions
- lengths and trusted digests
- producer revision/build identity
- dictionary identity
- validation status

Requirements:
- mixed or incomplete generations are detected before use
- rollback selects one complete prior generation

### PRE-044: SpectreDemo packaging
Status: TODO
Difficulty: Moderate

After portable formats stabilise:
- evaluate VHDX as a Windows packaging/mounting mechanism
- VHDX is packaging, not compression
- optionally combine with NTFS LZX for Windows-only distribution
- canonical Preimage data must remain usable without VHDX or NTFS-specific features

## Canonical dataset record

Production sizes, counts and compression measurements are authoritative in `DATASET.md`. Update that file first when measurements change; keep this register focused on status, dependencies and acceptance criteria.

## Rejected assumptions / constraints

- Dictionary deduplication: already done.
- 32-bit candidate IDs: insufficient.
- Plain streaming gzip/zstd for hot random-access data: unsuitable.
- NTFS LZX as canonical storage: not portable.
- VHDX as compression: incorrect; it is mainly packaging/sparse allocation.
