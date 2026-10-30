# Preimage Storage Roadmap

Updated: 2026-10-02

## Objective

Bring the complete production Preimage dataset below **500 GB** if practical while preserving all password candidates and avoiding a material performance regression.

The production dictionary is already deduplicated and contains exactly:

**11,901,699,218 passwords**

Current files:

| File | Role | Bytes | Approx. GiB |
|---|---|---:|---:|
| `bigdict.txt` | Canonical password dictionary | 136,291,884,307 | 126.93 |
| `bigdictsntlm.idx` | NTLM prefix index | 166,366,525,626 | 154.94 |
| `bigdict.msonline.pim` | MSOnline/CloudAP KDF cache | 451,566,283,906 | 420.56 |
| **Total** |  | **754,224,693,839** | **702.43** |

## Why generic compression is not enough

Windows NTFS LZX was tested on the real production data. The PIM achieved only about **1.1:1**, the dictionary achieved about **5:1**, and the complete dataset finished at about **1.4:1**, occupying **550,005,972,992 bytes (~512.24 GiB)**.

That is expected:
- PIM is mostly 32-byte PBKDF2-derived key material.
- IDX is mostly hash-derived prefix data.
- cryptographic material is intentionally high entropy and does not compress well.

Therefore the binary-cache savings must come mainly from **changing what is stored**, while the dictionary can benefit strongly from deployment-level or portable block compression. The completed Windows LZX result saves **204,218,720,847 bytes (~204.22 GB)** and leaves only **50,005,972,992 bytes (~50.01 GB)** to remove to reach the <500 GB decimal target.

VHDX can still be useful for packaging, mounting and portability on Windows, but VHDX by itself does not meaningfully compress these files.

## Design idea 1 — Candidate ordinal as the canonical identity

Both caches derive from the same deduplicated dictionary.

Today, billions of records repeat a 6-byte dictionary byte offset:
- PIM: 32-byte key + 6-byte offset
- IDX: 8-byte prefix + 6-byte offset

At 11.9 billion candidates, those repeated offsets consume tens of gigabytes.

The core redesign is to make **candidate ordinal N** the identity of a dictionary entry and move ordinal-to-plaintext resolution into a shared dictionary lookup layer.

This is especially natural for PIM because PIM records are created in dictionary order.

## Design idea 2 — PIM v2: 32-byte records — IMPLEMENTED

Current PIM v1:

```text
[32-byte derived key][6-byte dictionary offset]
= 38 bytes per candidate
```

Proposed PIM v2:

```text
[32-byte derived key]
= 32 bytes per candidate
```

The production PIM is not a one-record-per-dictionary-line file. Its exact length reveals:

```text
(451,566,283,906 - 64-byte header) / 38
= 11,883,323,259 records
```

That is **18,375,959 fewer records than the 11,901,699,218 dictionary lines**. The current CloudAP preparation code skips invalid-UTF8 lines and retains valid empty lines, so invalid UTF-8 is the leading explanation for the exact delta. This still needs whole-input confirmation because a resumed build's final log can report a total record count alongside an invocation-local invalid-UTF8 count.

For the same 11,883,323,259 records, implemented PIM v2 is:

```text
64 + (11,883,323,259 × 32)
= 380,266,344,352 bytes
= 354.15 GiB
```

The cache itself removes **71,299,939,554 bytes (~71.30 GB decimal)** from the current PIM, around **15.8%**. The implemented ordinal sidecar is projected at only **2,901,280 bytes (~2.77 MiB)** for the production record count, so combined v2 cache + sidecar is **380,269,245,632 bytes**.

### Why this should not hurt speed

A full PIM scan currently touches 38 bytes per candidate. PIM v2 touches 32.

The current ~451.6 GB PIM scans on Comino in about **2 minutes**, roughly **3.8 GB/s effective throughput**.

Because PIM v2 reduces bytes read per candidate, it should be neutral or faster on storage-bound systems.

No extra dictionary work is needed during a miss scan. Candidate-to-plaintext resolution only happens after a hit.

## Design idea 3 — Sparse ordinal-to-byte lookup — IMPLEMENTED

Removing per-record offsets means Preimage needs a cheap way to recover dictionary text after a match.

The implemented first version is intentionally simple:

```text
checkpoint every 65,536 accepted CloudAP candidates:
(PIM record ordinal -> dictionary byte offset)
```

Resolution:
1. find checkpoint before candidate N
2. seek to checkpoint offset
3. scan forward, skipping invalid-UTF8 dictionary lines while counting accepted candidates
4. return candidate N

This avoids building another multi-billion-entry offset table. The sidecar uses a 64-byte dictionary-bound header and 16-byte checkpoints, stored as `<cache>.ord`.

It is acceptable because plaintext resolution happens only after a candidate match and is therefore off the scan hot path.

## Design idea 4 — Seekable block-compressed dictionary

The 136,291,884,307-byte dictionary is ordinary text and should compress far better than PIM/IDX.

A plain `.zst` stream is not suitable because arbitrary candidate lookup would require stream decompression.

Preferred portable layout:

```text
dictionary.pdict
  header
  block table
  compressed block 0
  compressed block 1
  compressed block 2
  ...
```

Each block covers a known ordinal range and stores:
- first candidate ordinal
- candidate count
- compressed offset
- compressed length
- uncompressed length

Zstd is the first codec to test because decompression is fast and portable.

A successful cache lookup should decompress only the one dictionary block containing the hit.

A full PIM miss scan should never touch the compressed dictionary body.

The sparse ordinal sidecar and compressed-dictionary block table solve overlapping ordinal→location problems; design them as one compatible indexing scheme where possible rather than maintaining two independent mappings.

## Design idea 5 — Easy NTLM v2 win: 5-byte offsets — IMPLEMENTED

Before the harder succinct-index work, there is a low-risk reduction available. The dictionary is 136,291,884,307 bytes, so its largest byte offset fits in 37 bits. A 40-bit/5-byte offset is sufficient.

Current IDX entry:

```text
8-byte prefix + 6-byte offset = 14 bytes
```

Easy IDX v2:

```text
8-byte prefix + 5-byte offset = 13 bytes
```

Implemented as IDX2 with a 24-byte explicit versioned header and 13-byte entries. At 11,883,323,259 production records the projected file is **154,483,202,391 bytes**, saving **11,883,323,235 bytes (~11.88 GB decimal)** versus v1. Legacy v1 remains the default/readable format. This is compatible with later succinct-prefix work.

## Design idea 6 — NTLM requires a separate approach

Current NTLM entry:

```text
8-byte sorted hash prefix
6-byte dictionary offset
= 14 bytes
```

Because the index is sorted by hash, its order is not dictionary order.

That means PIM's simple “record number == candidate number” trick cannot be copied directly unless the dictionary itself is reordered.

Two main approaches should be evaluated.

### Option A — Reorder the canonical dictionary into NTLM order

Then:
- NTLM index position identifies the candidate
- PIM can be rebuilt against the same reordered dictionary
- per-entry dictionary offsets disappear

Advantages:
- very compact hot structures
- simple lookup path

Disadvantages:
- expensive migration
- changes canonical dictionary order
- requires all derived caches to be rebuilt consistently
- should not be attempted destructively until proven

### Option B — Keep dictionary order and split the mapping

Keep:
- a hot sorted prefix structure
- a separate compressed mapping from sorted index position to dictionary ordinal

This preserves the existing dictionary order.

Because there are 11,901,699,218 candidates:
- 32 bits are insufficient
- at least 34 bits are required

A plain 5-byte ordinal is better than a 6-byte byte offset but does not save enough by itself. The mapping therefore needs block/delta/succinct encoding to make the redesign worthwhile.

## Design idea 7 — Succinct sorted NTLM prefixes

The NTLM prefixes are sorted monotonic integers.

That allows data structures designed specifically for sorted integer sets, such as:
- Elias–Fano
- partitioned Elias–Fano
- blockwise delta encoding
- SIMD-friendly packed blocks

These can potentially store the 64-bit sorted prefix space in materially less than 8 bytes per candidate while still supporting lower-bound/range lookup.

This is the harder part of the project and should follow the low-risk PIM work.

## Design idea 8 — Evaluate 56-bit NTLM prefixes

A 56-bit prefix would reduce the hot NTLM key width further.

The existing lookup path already distinguishes prefix matches from full verified NTLM matches, so the key question is performance rather than inventing a new verification mechanism. Adopt this only if:
- actual collision-block size distribution is measured, including worst-case tails
- full NTLM verification remains mandatory before reporting success
- collision ranges are explicitly supported
- worst-case collision walks stay effectively interactive

This is a space/performance trade-off, not a correctness shortcut.

## Expected path to sub-500 GB

The target is not guaranteed until real compression and succinct-index measurements are available, but the intended model is approximately:

```text
PIM v2 cache               ~380.27 GB decimal
PIM ordinal sidecar         ~0.003 GB decimal
NTLM v2                    materially below current 166 GB
compressed dictionary      measured ~27 GB with NTFS LZX (5:1); portable zstd-block result TBD
small sidecars/metadata
----------------------------------------------------------
target                     <500 GB total
```

PIM v2 is the first certain saving.

The remaining gap must come primarily from:
- compact NTLM representation
- block-compressed dictionary for portable deployments
- optional NTFS LZX for Windows deployment, where the dictionary has already measured ~5:1

## Dataset integrity and migration philosophy

Future datasets will consist of several independently movable artifacts. Treat one validated generation as the deployment unit and bind it with a manifest containing artifact roles, versions, lengths, trusted digests, producer revision, dictionary identity and validation status.

Keep structural validity, dictionary identity, artifact integrity, completeness and behavioural compatibility as separate claims. Existing `check` commands do not prove all five.

Migration planning must include peak space for the old generation, new generation, temporary data and rollback headroom. A final dataset that fits below 500 GB can still require substantially more free space during conversion.

## Performance philosophy

Storage savings are not useful if Preimage becomes noticeably slower.

Rules:
- keep dictionary decompression off cache-scan hot paths
- preserve memory-mappable/sequential access where possible
- benchmark every new format against v1
- keep v1 readers until v2 is proven
- use measured production-like data rather than synthetic compression claims

Key current reference:
- ~451 GB PIM full scan on Comino: **~2 minutes**
- effective throughput: **~3.8 GB/s**

For external USB HDD deployment, smaller files may provide an even larger practical benefit because the disk, not CPU, becomes the bottleneck.

## Deployment note — Windows

A Windows VHDX remains useful as a packaging mechanism:
- one portable data container
- easy mount/unmount
- optional read-only mounting
- convenient Windows distribution

But:
- VHDX is not the primary compression strategy
- canonical Preimage data should remain portable outside VHDX
- NTFS LZX can be layered on for Windows-only deployment if benchmarks justify it
