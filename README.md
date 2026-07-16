# COE Corpus Ontology Enricher

COE v0.2 alpha is a standalone, offline terminology-analysis system with three deliberately separate execution profiles:

- a PHI-free synthetic vertical slice for deterministic regression testing;
- a private licensed-reference importer that builds immutable, cross-platform SQLite indexes; and
- a protected-local plaintext runner that emits aggregate coding evidence without paths, document identifiers, snippets, phrases, or unmapped text.

It is not a publication system or a clinical decision system. Candidate evidence is not acceptance, coding counts are not clinical prevalence, and all protected derivatives remain restricted.

## Install and test

Python 3.11 or newer and `uv` are required for development.

```bash
uv sync --extra dev
uv run ruff format --check .
uv run ruff check .
uv run pytest
```

## Synthetic regression slice

```bash
uv run coe demo create demo
uv run coe preflight snapshot demo/snapshot
uv run coe preflight reference demo/reference --environment synthetic
uv run coe run \
  --snapshot demo/snapshot \
  --reference demo/reference \
  --config demo/coe_config.json \
  --curation-snapshot genesis-v0 \
  --output out
```

This original v0 path remains synthetic-only and writes deterministic phrase and candidate-set artifacts for testing.

## Build the licensed reference set

The committed specification pins all seven normalized releases by file name, byte count, row count, SHA-256, canonical system URI, version, effective date, code format, alias policy, and active-status rule. The project-owner assertion authorizes controlled internal analysis and private derived indexes; it does not assert public redistribution rights.

```bash
uv run coe reference build-set \
  --source-dir /approved/path/to/normalized \
  --spec specs/licensed_terminologies.json \
  --entitlement governance/terminology_entitlement_assertion.json \
  --output private_build/references

uv run coe reference verify-set private_build/references
```

The set build is atomic. It does not copy raw publisher packages, normalized CSVs, access logs, or credentials into the result. LOINC related search names are preserved as metadata but are not treated as exact synonyms.

## Protected-local aggregate run

Protected processing requires an affirmative data-owner and privacy attestation matching `schemas/protected/1.0.0/data_use_attestation.schema.json`. The example is intentionally unapproved until an authorized person replaces its placeholders.

```bash
uv run coe protected run \
  --corpus /approved/read-only/plaintext \
  --attestation /approved/data_use_attestation.json \
  --index private_build/references/cpt.sqlite3 \
  --index private_build/references/hcpcs.sqlite3 \
  --index private_build/references/icd10cm.sqlite3 \
  --index private_build/references/icd10pcs.sqlite3 \
  --index private_build/references/loinc.sqlite3 \
  --index private_build/references/rxnorm.sqlite3 \
  --index private_build/references/snomed.sqlite3 \
  --output /restricted/run/output
```

Before consuming or transferring the aggregate result, verify its exact inventory, canonical encoding, artifact and semantic digests, run fingerprint, seven release identities, ambiguity coverage, and every exported code against the same indexes:

```bash
uv run coe protected verify \
  --output /restricted/run/output \
  --index private_build/references/cpt.sqlite3 \
  --index private_build/references/hcpcs.sqlite3 \
  --index private_build/references/icd10cm.sqlite3 \
  --index private_build/references/icd10pcs.sqlite3 \
  --index private_build/references/loinc.sqlite3 \
  --index private_build/references/rxnorm.sqlite3 \
  --index private_build/references/snomed.sqlite3
```

The current protected adapter accepts recursively discovered UTF-8 `.txt` files only. It rejects links, junctions, reparse points, hard links, and nonregular inputs, applies bounded resource limits, reads inputs in place, and atomically writes exactly:

- `coding_counts.jsonl` for uniquely grounded exact evidence;
- `ambiguity_counts.jsonl` for system-level ambiguous evidence; and
- `run_report.json` with restricted, path-free provenance and hashes.

Raw lexical material exists transiently in Python process memory; Python cannot guarantee secure erasure. Host access, swap, crash-dump, endpoint-protection, encryption, and retention controls therefore remain mandatory.

The current hard ceilings (10,000 files and 100,000,000 input bytes) make this a bounded qualification slice, not a full-corpus production batch engine. Larger approved corpora require a separately tested partition/checkpoint design rather than raising these guards ad hoc.

## Windows and GPU host

The portable deployment is native-Windows-first so it also works on Windows Server hosts where Docker Desktop may not be supported. See [deploy/windows/README-WINDOWS.md](deploy/windows/README-WINDOWS.md).

```bash
uv build
uv run python tools/build_windows_bundle.py \
  --wheel dist/coe_corpus_ontology_enricher-0.2.0a1-py3-none-any.whl \
  --output artifacts/coe-windows-0.2.0a1.zip

uv run python tools/build_reference_bundle.py \
  --reference-set private_build/references \
  --output private_build/coe-private-references.zip
```

The application archive contains no terminology payload or patient data. The second archive is a controlled licensed asset and contains no patient data.

`coe hardware probe --require-nvidia` fails closed if `nvidia-smi` cannot report an NVIDIA GPU. Exact phrase mining and SQLite lookup intentionally run on CPU; this release does not pretend that those operations benefit from CUDA. The GPU is reserved for a later, separately evaluated semantic-candidate stage with pinned model and runtime provenance.

## Current boundaries

- Patient inputs and every protected output stay on the authorized host and are treated as restricted data.
- There is no network, telemetry, automatic acceptance, curation, RDF/FHIR publication, or public export path.
- The protected adapter has not been connected to a live database, PDF/DOCX extraction path, or a specific remote patient-data layout.
- The local attestation is an unsigned procedural gate; an authorized reviewer must still verify its corpus scope, purpose, validity window, and approval status before each production run.
- CPT source metadata identifies the private Athena export date, not an authoritative CPT edition; publication remains blocked until that edition and destination rights are recorded.
- GPU model, VRAM, driver, Windows edition, data layout, and WSL compatibility must be measured on the target host rather than inferred.

See [SECURITY.md](SECURITY.md), [docs/CONTROLLED_DEPLOYMENT.md](docs/CONTROLLED_DEPLOYMENT.md), and the full [COE design and plan](COE_DESIGN_AND_PLAN.md) for the remaining production gates.
