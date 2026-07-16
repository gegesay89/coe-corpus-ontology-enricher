# COE protected Windows bundle

This directory is the native-Windows-first deployment scaffold for COE v0. It
is intended for a controlled Windows NVIDIA host that already contains approved
patient data. The portable bundle contains application code only: no patient
data, licensed terminology payloads, model weights, credentials, host
identifiers, or connection details.

The v0 phrase miner and licensed terminology matcher run on the **CPU**. A GPU
can be required as a deployment capability check, but it does not accelerate
the current exact matcher. CUDA is reserved for a future, separately approved
semantic candidate stage; candidates from that stage must remain pending until
curation and publication gates pass.

## What v0 accepts and exports

The protected runner accepts a clean directory tree containing only UTF-8
`.txt` files. The Windows production preflight fails if any other file type is
present, and a corpus with no eligible plaintext fails.
PDF, Word, DICOM, image, audio, email, archive, and database sources therefore
need a separately reviewed extraction adapter that writes UTF-8 plaintext into
an approved, read-only corpus directory. Do not point v0 at a live EHR database
or assume that it performs OCR or document conversion.

The protected runner emits only:

- `coding_counts.jsonl`, aggregate exact-match counts by terminology coding;
- `ambiguity_counts.jsonl`, aggregate ambiguous-match counts by terminology;
- `run_report.json`, path-free processing totals, limits, release identities,
  hashes, and limitations.

The output intentionally contains no patient identifier, document identifier,
source path, filename, phrase, snippet, or unmapped value. It is still classified
`protected_aggregate`; it is not de-identified or approved for public release.

## Security model

- Transfer the code bundle separately from patient data and terminology assets.
- Finish software installation before protected inputs are mounted or exposed.
- Use BitLocker-encrypted NTFS storage and a dedicated non-administrator runner.
- Grant that runner read/execute only on corpus, reference set, attestation, and
  application inputs; grant modify only on the restricted output root.
- Native preflight requires a program-specific outbound firewall block for the
  dedicated Python executable, unless the operator deliberately uses the
  conspicuous `-AllowHostNetwork` override. This is defense in depth, not proof
  of isolation: production PHI runs also require a host/VM-wide egress-deny or
  an equivalently isolated network boundary.
- The optional container has no network, no ports, a read-only root filesystem,
  a numeric non-root user, no Linux capabilities, and read-only input mounts.
  Its only writable host mount is a unique empty directory created for that
  one run; the general output root and prior results are never mounted.
- Both routes hash the corpus, reference set, and attestation before and after
  execution and fail if an input changes.
- A data-use attestation is mandatory. Terminology license ownership does not
  replace patient-data owner, privacy, retention, or security approval.

Never nest the application, reference set, corpus, or output inside one another.

## 1. Build the code-only transfer bundle

Build the application wheel on a trusted packaging machine, then run PowerShell
from the repository root:

```powershell
.\deploy\windows\Build-PortableBundle.ps1 `
  -WheelPath ".\dist\coe_corpus_ontology_enricher-0.2.0a1-py3-none-any.whl" `
  -OutputPath "D:\Transfer\coe-windows-v0"
```

Use `-WheelhousePath` only for pre-reviewed, locally downloaded dependency
wheels. The builder copies an explicit allowlist and produces
`checksums.sha256`. It accepts only the
`coe_corpus_ontology_enricher-VERSION-py3-none-any.whl` pattern, reads the
embedded wheel `METADATA` with .NET ZIP APIs, and binds its package, version,
path, and SHA-256 into the runtime manifest. It cannot package patient data,
terminology payloads, or model weights. Independently sign or record the
completed archive digest; the internal checksum file detects corruption but is
not publisher authentication.

Copy the bundle to Windows through the approved encrypted transfer channel.
Transfer licensed terminology sources or built indexes separately under their
license controls.

## 2. Inspect the target without disclosing it

Run the sanitized host-facts collector before choosing dependencies or the
optional WSL2 route:

```powershell
.\Collect-HostFacts.ps1 > .\host-facts.safe.json
```

It reports only OS/build/architecture, RAM, NVIDIA model/count/VRAM/driver,
Python/WSL/Docker availability, and capability flags. It omits hostname,
username, IP, serial/UUID, RDP details, and every patient path.

This report is inventory, not readiness approval. Before patient processing,
an operator must separately verify BitLocker or equivalent encryption, local
fixed NTFS storage, adequate free space, supported NVIDIA driver/CUDA
compatibility, host/VM-wide egress denial, endpoint and crash-dump policy, a
dedicated non-owner runtime identity, and effective read-only access to inputs.
UNC/network patient paths are outside this v0 qualification boundary.

If the patient-data format is unknown, inspect one explicitly supplied root:

```powershell
.\Inspect-InputLayout.ps1 -PatientDataRoot "D:\ProtectedSource" `
  > .\input-layout.safe.json
```

This report contains only total files, total bytes, reparse-point count, and
sanitized extension counts. It does not open file content, follow reparse
points, or emit paths or filenames. Unknown suffixes are grouped as `<other>`.
Use the result to decide which extraction adapter is needed; it does not make a
non-text corpus runnable.

## 3. Install natively and offline

Install an approved Python 3.12 x64 build and verify its installer hash. From an
elevated PowerShell prompt, verify and install the bundle and create the
program-specific outbound block:

```powershell
.\Install-Native.ps1 `
  -BundleRoot $PWD `
  -InstallRoot "C:\ProgramData\COE\App" `
  -BootstrapPython "py.exe" `
  -ConfigureOutboundBlock
```

The installer verifies the exact file inventory and hashes, creates an isolated
virtual environment, and runs pip with `--no-index`. Replacement requires
`-Overwrite` and uses a rollback directory. Before publishing the replacement,
it verifies the staged copy again and requires the installed distribution
package, version, command version, wheel path, and wheel hash to match either
the supported Python `runtime_manifest.json` or PowerShell
`bundle-manifest.json` contract.

## 4. Build and verify all licensed indexes

On the protected host, place the seven normalized source CSV files under one
licensed source directory. Their filenames, schemas, record counts, release
identities, and pinned SHA-256 values must match `specs/licensed_terminologies.json`.
Keep the source directory private and read-only after transfer.

Build the complete set atomically with the approved entitlement assertion:

```powershell
& "C:\ProgramData\COE\App\.runtime\Scripts\python.exe" -m coe reference build-set `
  --source-dir "D:\LicensedTerminologySource" `
  --entitlement "C:\COE\Control\terminology_entitlement_assertion.json" `
  --output "C:\COE\References\release-set-001"

& "C:\ProgramData\COE\App\.runtime\Scripts\python.exe" -m coe reference verify-set `
  "C:\COE\References\release-set-001"
```

The Windows production wrapper requires exactly these seven immutable SQLite
indexes: CPT, HCPCS, ICD-10-CM, ICD-10-PCS, LOINC, RxNorm, and SNOMED CT. The
wrapper verifies the reference-set manifest, checksums, entitlement binding,
exact file inventory, and every index before a patient run.

The installed wheel supplies the pinned default specification. Pass `--spec`
only when deploying a separately reviewed replacement specification with a
matching application release.

## 5. Prepare the protected corpus and attestation

A recommended layout is:

```text
C:\ProgramData\COE\App       application only
C:\COE\References            verified seven-index set, read-only
D:\COE\Corpus                approved UTF-8 plaintext, read-only
C:\COE\Control               attestation and controlled specifications
C:\COE\Runs                  restricted output, writable to runner
C:\COE\Models                future semantic models only; unused by v0
```

Copy `config/protected_data_attestation.example.json` to the controlled
directory. The example deliberately fails because `approved` is false and its
approval references are placeholders. An authorized reviewer must set:

- `profile` to `protected_phi_local`;
- `approved` to `true` only for the specific controlled use;
- non-placeholder `data_owner` and `privacy` approval references, plus
  `security` when required;
- the applicable `retention_policy_id`; and
- `output_classification` to `protected_aggregate`.

The application accepts exactly those attestation fields. Record approval
lifecycle and revocation in the referenced governance system; regenerate or
withdraw the local attestation when approval changes. The runner intentionally
fails if the current Windows identity or any of its groups has write-capable ACL
rights on the corpus, reference set, or attestation. Use a dedicated runner
instead of weakening this check.

The JSON attestation is an unsigned procedural control, not proof of who
approved it. The operator must bind its approval references to the exact corpus,
purpose, host, and validity window in the authoritative governance system and
confirm that approval immediately before a production run.

## 6. Run the native protected profile

```powershell
& "C:\ProgramData\COE\App\Run-Coe.ps1" `
  -CorpusPath "D:\COE\Corpus\approved-plaintext-001" `
  -ReferenceSetPath "C:\COE\References\release-set-001" `
  -AttestationPath "C:\COE\Control\data_use_attestation.json" `
  -OutputPath "C:\COE\Runs\run-001"
```

Optional bounded overrides are `-MaxFiles`, `-MaxTotalBytes`,
`-MaxTotalTokens`, `-MaxTotalNgrams`, `-MaxNgramTokens`, and
`-MaxCandidatesPerPhraseSystem`. Defaults and hard ceilings are 10,000 files,
100,000,000 bytes, 5,000,000 tokens, 10,000,000 n-grams, 4 default/8 maximum
n-gram tokens, and 100 candidates per phrase/system. Lower the limits for an
initial qualification run; the application will not accept values above its
safety ceilings.

These ceilings define a qualification slice. They are not evidence that a full
patient corpus fits in v0; larger workloads require an approved partitioned,
checkpointed design and capacity tests.

`-RequireNvidia` verifies NVIDIA visibility and records that check. Exact
matching still runs on CPU. `-Overwrite` is required to replace an existing
output. Avoid `-AllowHostNetwork` for protected runs; offline environment
variables and the program firewall rule are defense in depth. The production
enforcement boundary must be host/VM-wide egress denial or equivalent
isolation.

## Optional WSL2 Docker route

Use this route only after the sanitized host report proves that WSL2, Docker,
and GPU pass-through are supported. Docker Desktop GPU support depends on its
WSL2 backend and is not a supported Windows Server deployment. On a Windows
Server or cloud GPU host, prefer native Windows unless WSL2/nested
virtualization and the chosen container runtime are independently qualified.
Do not install a Linux display driver in WSL; the supported Windows NVIDIA
driver provides GPU pass-through.

The base image must already exist locally and be referenced by digest. It must
contain Bash and Python 3.12; every Python dependency must be in the offline
wheelhouse. The wrapper refuses a tag-only or unavailable base image.

```powershell
& "C:\ProgramData\COE\App\Invoke-WslDocker.ps1" `
  -CorpusPath "D:\COE\Corpus\approved-plaintext-001" `
  -ReferenceSetPath "C:\COE\References\release-set-001" `
  -AttestationPath "C:\COE\Control\data_use_attestation.json" `
  -OutputRoot "C:\COE\Runs" `
  -OutputName "run-001" `
  -PythonBaseImage "approved-python-image@sha256:REPLACE_WITH_64_HEX" `
  -Build
```

Compose uses `pull_policy: never`, build network isolation, runtime
`network_mode: none`, no ports, numeric non-root execution, a read-only root,
all capabilities dropped, `no-new-privileges`, and read-only mounts for corpus,
reference set, and attestation. After an optional build, the wrapper resolves
the fixed `coe-protected-local:0.2.0a1` tag to an immutable
`sha256:<64-hex>` image ID, re-inspects that ID before and after execution, and
records it in the safe run result. The run uses the image ID, never the mutable
tag.

The wrapper creates a unique empty staging directory beside the requested
result and mounts only that directory writable. The container can write only
the fixed `result` child. Windows verifies that staged result against the exact
licensed reference set, atomically renames it to `OutputRoot\OutputName`,
verifies it again after publication, and rolls back an approved `-Overwrite`
replacement on failure. Staging is removed on both success and failure. The
output root must be bidirectionally disjoint from the corpus, reference set,
attestation directory, installed runtime, and deployment scripts.

The NVIDIA device reservation makes a GPU visible for qualification and future
work; the default `COE_REQUIRE_GPU=0` accurately reflects the CPU-only exact
stage.

## Verify, quarantine, and troubleshoot

Verification runs automatically and can be repeated independently:

```powershell
.\Verify-Run.ps1 `
  -OutputPath "C:\COE\Runs\run-001" `
  -ReferenceSetPath "C:\COE\References\release-set-001" `
  -PythonExe "C:\ProgramData\COE\App\.runtime\Scripts\python.exe"
```

It rejects an invalid or oversized report, missing/extra/non-file/reparse
artifacts, size/hash/row-count mismatches, oversized JSONL rows, unexpected JSON
fields, wrong output profile, release identities that differ from the verified
seven-index reference set, and codes absent from the exact release catalog. It
streams bounded JSONL rows instead of loading a large result into memory.

On failure, quarantine any output, preserve only the safe JSON status, and do
not copy artifacts off the protected host. Never put patient paths, filenames,
note content, credentials, host identifiers, terminology payloads, or raw tool
stderr into tickets or chat messages.
