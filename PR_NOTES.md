# PR notes

## Multi-GPU CloudAP / mode 33700 field result

Observed on Comino with 6 × RTX 4090 during the same ~126.9 GiB CloudAP cache build. The multi-GPU run completed successfully end-to-end after resuming an existing single-GPU `.partial` cache.

- CPU-only run:
  - Reported ETA: ~11 h for the same corpus
  - Treat as an approximate field baseline, not a controlled benchmark

- Single-GPU run:
  - 1 × RTX 4090
  - GPU utilisation: ~100%
  - Progress observed: 808 MiB / 126.9 GiB
  - Reported remaining time: ~5 h
  - Implied remaining-processing rate: ~25.2 GiB/h

- Multi-GPU run:
  - 6 × RTX 4090
  - GPU utilisation: ~70–80% per GPU
  - Progress observed: 73.56 GiB / 126.93 GiB
  - Reported remaining time: ~29 min
  - Implied remaining-processing rate: ~110.4 GiB/h

- Observed end-to-end scaling from the live ETA/rate figures: ~4.38× versus one GPU.
- Relative to the earlier ~11 h CPU-only ETA, the six-GPU run is roughly ~9.6× faster end-to-end.
- The single-GPU run was roughly ~2.2× faster than the CPU-only baseline.
- At the observed six-GPU rate, a full 126.9 GiB corpus is roughly a ~69 minute job if throughput remains steady.
- The resumed multi-GPU run completed successfully, validating both multi-device execution and compatibility with the existing version-1 resumable cache format.
- Scaling is intentionally reported as an observed field result rather than a controlled benchmark; CPU-side password preparation, transfers, synchronisation, and cache output prevent linear 6× scaling.

Implementation detail relevant to the PR: each KDF batch is split into contiguous shards across all visible CUDA devices, each worker selects its device with `cudaSetDevice()`, and results are reassembled in dictionary order. Cache format remains version 1 and existing single-GPU `.partial` builds remain resumable.

## CLI consistency follow-up

- Unified ordinary hash/index and CloudAP queries under `preimage search`.
- Ordinary example: `preimage search -a ntlm -c ntlm.idx -d words.txt <hash>`.
- CloudAP example: `preimage search -c words.cloudap33700.pim -d words.txt '<33700-target>'`; target type is auto-detected.
- `-c` is now the short form for cache/index and `-d` for dictionary.
- Successful searches print `Password found: <plaintext>` in green; misses print `Password not found` in red.
- Only full hash matches are reported as found; prefix-collision candidates are not promoted to successful results.
- Removed the user-facing CloudAP `--backend` selector. CUDA is selected automatically when compiled in and a CUDA device is available; otherwise the CPU backend is used.
- Added a default user search config (`algorithm`, `cache`, `dictionary`) with CLI values taking precedence. Relative paths resolve relative to the config file.
- Default config paths: Linux `$XDG_CONFIG_HOME/preimage/config.toml` or `~/.config/preimage/config.toml`; Windows `%APPDATA%\\preimage\\config.toml`; `PREIMAGE_CONFIG` overrides the location.
- Added CLI regression coverage for NTLM hit/miss wording, CloudAP auto-backend build plus unified search, default-config resolution, and absence of the old backend flag from help.
