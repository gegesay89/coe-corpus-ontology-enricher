# Controlled Windows deployment boundary

The portable application is designed to be copied to a controlled Windows GPU host. It does not assert that an uninspected host is ready. The included host-facts check is sanitized inventory only; production also requires operator verification of encrypted local NTFS storage, free space, supported NVIDIA/CUDA compatibility, host/VM-wide egress denial, endpoint/crash-dump policy, and a dedicated non-owner runtime identity.

Recommended native Windows layout:

```text
C:\COE\App           application bundle and virtual environment
C:\COE\References    licensed SQLite indexes, read-only during analysis
C:\COE\Models        approved, hashed model files, read-only
C:\COE\Runs          access-controlled writable output
D:\PatientData        patient input, read-only
```

The drive letters are examples. The runtime takes explicit paths and never discovers patient folders automatically.

## Two execution stages

1. Exact terminology matching streams normalized reference CSVs into immutable SQLite indexes and performs lexical lookup on CPU. This stage is deterministic and cross-platform.
2. GPU semantic retrieval is a separately versioned, optional stage. It must pin the model, tokenizer, weights, CUDA/PyTorch versions, vector dimensions, and build configuration. It only proposes pending candidates and is not enabled in this release.

The native Windows route is the default because Windows Server hosts may not support Docker Desktop. WSL2/Docker is included only as a conditional route when the host-facts report confirms compatible Windows, WSL, Docker, and NVIDIA support.

## Patient-data rule

Inputs are processed in place and read-only. No patient content is included in either transfer archive. Protected output never contains source text, paths, identifiers, snippets, phrases, or unmapped text, but it remains classified as restricted patient-derived data and must stay on the machine.

The v0 Windows preflight accepts a clean UTF-8 `.txt`-only corpus and rejects mixed file types. Its 100 MB/10,000-file ceiling is a qualification slice. PDF, Office, DICOM, database, UNC/network, and larger partitioned inputs require separately reviewed adapters and capacity controls.

The local JSON attestation and ACL inspection are procedural gates, not cryptographic authorization or a complete effective-access proof. An authorized operator must verify corpus-specific approval and effective read-only access immediately before every production run.
