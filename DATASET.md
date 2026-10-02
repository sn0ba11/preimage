# Production Dataset Record

Updated: 2026-10-02

This file is the canonical record for the current production Preimage dataset.
Planning documents should refer here rather than duplicating measurements where possible.

## Generation identity

Status: production measurements supplied by operator; artifact digests and producer revision still to be recorded from the production host.

## Source dictionary

- File: `bigdict.txt`
- Logical size: **136,291,884,307 bytes**
- Candidate lines: **11,901,699,218**
- Deduplication: already completed upstream
- Largest possible byte offset: < 2^37 bytes, therefore a 40-bit/5-byte offset is sufficient

## NTLM index

- File: `bigdictsntlm.idx`
- Logical size: **166,366,525,626 bytes**
- Legacy record size: **14 bytes**
- Legacy layout: 8-byte hash prefix + 6-byte little-endian dictionary byte offset
- Derived record count: **11,883,323,259**
- Division remainder: zero

Calculation:

```text
166,366,525,626 / 14 = 11,883,323,259
```

## MSOnline / CloudAP cache

- File: `bigdict.msonline.pim`
- Logical size: **451,566,283,906 bytes**
- Header size: **64 bytes**
- Legacy record size: **38 bytes**
- Legacy layout: 32-byte derived key + 6-byte little-endian dictionary byte offset
- Derived record count: **11,883,323,259**
- Division remainder: zero

Calculation:

```text
(451,566,283,906 - 64) / 38 = 11,883,323,259
```

## Count reconciliation

- Dictionary lines: **11,901,699,218**
- IDX entries: **11,883,323,259**
- PIM records: **11,883,323,259**
- Difference: **18,375,959**

Current source inspection shows CloudAP rejects invalid-UTF8 dictionary lines and retains valid empty lines. NTLM also rejects invalid UTF-8 through the NTLM algorithm. This is the leading explanation for the matching IDX/PIM count delta, but production-wide confirmation still requires either a fresh whole-input accounting run or another authoritative source covering the complete build.

A final log from a resumed CloudAP build is not sufficient evidence by itself: total record count can include resumed records while the reported invalid-UTF8 counter covers only the current invocation.

## Windows NTFS LZX deployment measurement

Original logical dataset:

- **754,224,693,839 bytes**
- approximately **702.43 GiB**

Measured LZX results:

- PIM: approximately **1.1:1**
- Dictionary: approximately **5:1**
- Whole dataset: approximately **1.4:1**
- Final allocated size: **550,005,972,992 bytes**
- approximately **512.24 GiB**

Allocated-space saving:

- **204,218,720,847 bytes**
- approximately **204.22 GB decimal**
- approximately **27.1%**

Remaining gap to a strict 500 GB decimal deployment target:

- **50,005,972,992 bytes**
- approximately **50.01 GB**

These are Windows filesystem allocation measurements, not portable-format sizes.

## Performance reference

Reported production observation:

- Full current PIM scan on Comino: approximately **2 minutes**
- Effective logical processing rate: approximately **3.8 GB/s**

This is a reported reference, not yet a reproducible benchmark record. Before accepting a format performance comparison, record:
- exact revision/build
- CPU/GPU/storage
- filesystem and compression state
- warm/cold cache state
- exact command and target
- repeated elapsed times

## Validation dimensions

Keep these claims separate:

1. Structural validity
2. Dictionary identity
3. Artifact integrity
4. Completeness
5. Behavioural compatibility

A successful `preimage check` does not by itself establish all five.

## Missing production metadata

Still to capture:
- SHA-256 of all three source artifacts
- producer revision/build for IDX and PIM
- authoritative full-input invalid-UTF8 count
- whether the dictionary line count includes a final unterminated line
- exact Comino benchmark conditions
