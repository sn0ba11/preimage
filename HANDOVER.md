# Preimage Storage Optimisation Handover

Date: 2026-10-02

## Context

Preimage is now proven working for:
- NTLM
- MSOnline / CloudAP mode 33700

Both workflows use the same deduplicated production dictionary.

The immediate goal is to reduce the complete production data footprint from ~702.43 GiB to below 500 GB if practical, without sacrificing candidate coverage or materially reducing speed.

## Exact production figures

Dictionary:
- file: `bigdict.txt`
- size: **136,291,884,307 bytes**
- candidates: **11,901,699,218**
- already deduplicated

NTLM index:
- file: `bigdictsntlm.idx`
- size: **166,366,525,626 bytes**
- current entry format: 8-byte hash prefix + 6-byte dictionary byte offset = 14 bytes

MSOnline/CloudAP PIM:
- file: `bigdict.msonline.pim`
- size: **451,566,283,906 bytes**
- current record format: 32-byte derived key + 6-byte dictionary byte offset = 38 bytes

Total:
- **754,224,693,839 bytes**
- approximately **702.43 GiB**

## Measured compression result

A real Windows NTFS LZX compression pass completed on the PIM.

Results:
- PIM approximately **1.1:1**
- Dictionary approximately **5:1**
- Full dataset approximately **1.4:1**
- Final allocated size: **550,005,972,992 bytes (~512.24 GiB)**
- Saving versus logical dataset: **204,218,720,847 bytes (~204.22 GB, ~27.1%)**
- Remaining gap to <500 GB decimal: **50,005,972,992 bytes (~50.01 GB)**

Conclusion:
- PIM/IDX contain mostly high-entropy cryptographic material, so binary-cache format redesign is still useful
- the dictionary compresses extremely well
- the completed LZX result means the Windows deployment is already close to the target; the easy v2 reductions may be sufficient without requiring the most aggressive succinct-index design

## Important performance baseline

On Comino, the current ~451 GB PIM scans in approximately **2 minutes**.

That is around **3.8 GB/s effective scan/read throughput**.

Do not merge a storage optimisation that materially regresses this without explicit justification.

## Start here — easy work for Claude

The PIM v2 implementation is now complete on the CPU path and format-compatible with the existing v1 reader.

### PIM v2 design

Current:
```text
32-byte derived key
6-byte dictionary byte offset
= 38 bytes/record
```

v2:
```text
32-byte derived key only
= 32 bytes/record
```

The candidate ordinal is implied by the record position.

Important production detail:
- Dictionary lines: **11,901,699,218**
- PIM records inferred exactly from the current file: **11,883,323,259**
- Difference: **18,375,959**

The current PIM therefore does not contain one record for every dictionary line. Source review shows the CloudAP build path skips invalid-UTF8 lines while valid empty lines still produce records. Treat invalid UTF-8 as the leading explanation for the 18,375,959 delta, but confirm it with whole-input accounting before relying on it. A resumed build's final log cannot by itself prove the total because its invalid-UTF8 counter is invocation-local.

For the same 11,883,323,259 records, v2 size is:
- **380,266,344,352 bytes including the 64-byte header**
- **354.15 GiB**

This saves **71,299,939,554 bytes (~71.30 GB decimal)**, about **15.8%** of the current PIM.

### Why this works

The CloudAP cache is generated in dictionary order.

Do **not** define record N as raw dictionary line N. Define it as the N-th **accepted CloudAP candidate** (valid UTF-8 under the current semantics).

Implemented v2 removes the per-record byte offset. A sibling `<cache>.ord` sidecar maps accepted-candidate ordinal → dictionary byte offset using a 65,536-candidate checkpoint stride and skips invalid-UTF8 lines during bounded forward resolution.

After a hit, Preimage can resolve ordinal N back to plaintext through a sparse dictionary index.

The ordinal lookup is not part of the full scan hot path.

### Implementation status

Completed:
1. Production counts and storage baseline recorded.
2. v1 compatibility pinned with immutable/writer-independent evidence.
3. IDX2 5-byte offsets implemented.
4. Sparse accepted-candidate ordinal sidecar implemented.
5. Explicit PIM v2/version 2 support implemented.
6. v2 records are exactly 32 bytes; open/check/search understand both versions.
7. CPU v2 builder implemented; CUDA v2 path uses the same record ordering logic.
8. v2 torn-record repair/resume uses the sidecar rather than rescanning the dictionary.
9. Conditional CUDA test covers CPU/CUDA byte identity for v2 cache + sidecar, including long UTF-16 passwords; it still needs execution on a CUDA-capable host.

Next: benchmark production v1 vs v2 on Comino (PRE-013), then recompress the real v2 dataset and record the actual deployed footprint.

Do not remove v1 support.

## Sparse dictionary ordinal index

First version should be simple, not clever.

Store checkpoints every K accepted CloudAP candidates:

```text
PIM record ordinal -> dictionary byte offset
```

To resolve hit N:
- jump to checkpoint <= N
- seek to its byte offset
- scan forward a bounded range
- skip invalid-UTF8 lines while counting accepted candidates
- return accepted candidate N

This is intentionally off the hot path.

Do not create a full 11.9B-entry offset table.

## Dictionary compression work

The dictionary is likely the best compression candidate because it is text.

Do not replace it with a monolithic `.zst`.

Instead prototype a seekable block-compressed format after the basic PIM v2 work is stable.

Suggested:
- zstd blocks
- each block owns a known ordinal range
- block table maps ordinals to compressed offsets
- optional small LRU decompression cache

A full PIM miss scan must not decompress dictionary blocks.

The production dictionary has now measured about **5:1** under NTFS LZX. Still benchmark portable zstd block sizes (for example 64 KiB / 256 KiB / 1 MiB uncompressed) for both ratio and one-block decompression latency before choosing the canonical portable format. Design the block table to reuse the ordinal sidecar mapping where practical.

## NTLM work

The easy NTLM 5-byte-offset task is now **implemented** as IDX2. It uses a 24-byte explicit header and 13-byte entries, is created with `--compact-index`, and is understood by build/sort/check/mmap lookup. Legacy headerless v1 remains the default/readable format. At the current record count the projected production saving is **11,883,323,235 bytes (~11.88 GB decimal)**. Full workspace tests pass, including a real external-merge IDX2 header-preservation test. Production-scale throughput still needs benchmarking before IDX2 becomes the default.

The deeper NTLM redesign remains harder.

The NTLM redesign is harder.

Current index:
- 8-byte sorted prefix
- 6-byte dictionary byte offset

The index is hash-sorted, so record position does not naturally equal dictionary ordinal.

The dictionary has 11,901,699,218 entries, therefore:
- 32-bit candidate IDs do not fit
- at least 34 bits are required for ordinals
- current byte offsets fit in 37 bits, making a 5-byte offset an immediate safe format reduction

Candidate ideas documented in `ROADMAP.md`:
- dictionary reordered into NTLM order
- separate compressed ordinal mapping
- Elias–Fano / succinct sorted prefix representation
- 56-bit prefixes with mandatory full NTLM verification

Do not destructively reorder the production dictionary at this stage.

## Compatibility requirements

- v1 PIM must remain readable
- v1 IDX must remain readable
- v2 files need explicit versioning
- no silent interpretation of one format as another
- production v1 data remains the fallback until v2 checks pass
- treat one complete dataset generation as the deployable unit, identified by a manifest containing versions, lengths, trusted digests, producer revision, dictionary identity and validation status
- failed migration must leave the previous validated generation usable

## Correctness tests

Do not treat one successful `check` as proving everything. Keep structural validity, dictionary identity, artifact integrity, completeness and behavioural compatibility as separate validation claims.

For both v1 and v2:
- known NTLM hit
- known NTLM miss
- known CloudAP hit
- known CloudAP miss
- first/middle/last candidate resolution
- final dictionary line with and without newline
- interrupted PIM build resume
- CPU-to-CUDA and CUDA-to-CPU resume where supported
- corruption/truncation checks

## Performance gates

CloudAP:
- current full PIM scan on Comino: ~2 minutes
- v2 should be neutral or faster

NTLM:
- current lookup should remain effectively interactive

Dictionary:
- decompression/resolution must remain off scan hot paths

USB HDD:
- reduced file size should improve wall-clock performance because storage bandwidth becomes the bottleneck

## Files added for this work

- `TASK_REGISTER.md` — concrete work items and acceptance criteria
- `ROADMAP.md` — design rationale, size model, and future options
- `HANDOVER.md` — this implementation handover

## Recommended first Claude task

Start with PRE-001 and PRE-002:
- reconcile counts/provenance and record a reproducible baseline
- inventory and strengthen the existing compatibility evidence

PRE-029, PRE-010 and PRE-011 are complete. PRE-012 is implemented with CPU validation complete and CUDA runtime validation pending on a CUDA-capable host. The next active task is **PRE-013: production PIM v1 vs v2 benchmarking on Comino**, followed by rebuilding/recompressing the production v2 cache to measure the real storage saving.

Do not jump into the succinct NTLM work until the easy v2 reductions are proven and benchmarked.
