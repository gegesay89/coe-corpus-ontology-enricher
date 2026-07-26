# COE Corpus Ontology Enricher

COE v0.4 alpha is a standalone, offline corpus-ontology-enrichment system with three deliberately separate execution profiles:

- a PHI-free synthetic vertical slice for deterministic regression testing, with a completable hash-chained curation workflow;
- a private licensed-reference importer that builds immutable, cross-platform SQLite indexes; and
- a protected-local plaintext runner that produces the corpus-enrichment outputs — coding frequency, mention-context breakdown, dataset lexical forms (synonym evidence), unmapped candidate terms, and code co-occurrence associations — under a small-cell suppression floor, a deterministic scrub filter, and an explicit lexical-output attestation gate.

It is not a publication system or a clinical decision system. Candidate evidence is not acceptance, coding counts are lexical evidence across every mention context rather than clinical prevalence, association rows are co-mention statistics and not clinical relationships, and all protected derivatives remain restricted.

## Install and test

Python 3.11 or newer and `uv` are required for development.

```bash
uv sync --extra dev
uv run ruff format --check .
uv run ruff check .
uv run pytest
```

## Mention context

Every mention is assigned exactly one context label, so counts partition cleanly and a negated or family-history mention never masquerades as a finding:

| Label | Meaning |
|---|---|
| `current_clinical` | affirmed, patient, present — the clinical default |
| `negated` | the sentence asserts the concept is absent ("no evidence of", "denies", "ruled out") |
| `non_patient` | the mention belongs to a family member or other person ("family history of", "mother had") |
| `historical` | the patient's past rather than the present ("history of", "status post", "prior") |

Precedence is negated > non_patient > historical > current_clinical: a negated family-history mention is, first of all, not an assertion about the patient. Scoping is bounded by sentence, word distance, and scope-breaking conjunctions ("no fever **but** reports cough" leaves the cough affirmed), and EHR section headers (`Family History:`, `Past Medical History:`) scope their block until a header like `Assessment:` resets it.

The rules are a conservative lexical screen, not a parser. They cannot resolve nested or long-range scope, so `current_clinical` remains lexical evidence rather than a clinical finding.

## Matching

Phrase-to-code resolution is exact-first with deterministic, grounding-safe variants: punctuation-compacted forms, a curated unambiguous clinical abbreviation map (for example `HTN` resolving to a release's `hypertension` designation), and conservative singularization. Every emitted code must exist in a pinned release — variants add dictionary lookups, never fabricated codes. Sentence mining treats a single newline as soft so hard-wrapped clinical text keeps its phrases; blank lines, terminal punctuation, and bullet lines split.

## Synthetic regression slice and curation

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

Curation is completable: decisions are recorded as an append-only, hash-chained JSONL file, pinned by an immutable snapshot, and applied on the next run (acceptance states become `curator_accepted` or `curator_rejected`; everything else stays `pending`).

```bash
uv run coe curation decide \
  --decisions decisions.jsonl \
  --form "alpha finding" \
  --system urn:example:system \
  --release 00000000-0000-4000-8000-000000000001 \
  --code U1 --decision accepted --curator reviewer-1

uv run coe curation snapshot \
  --decisions decisions.jsonl --id review-1 --scope demo --output curation_snapshot.json

uv run coe run \
  --snapshot demo/snapshot --reference demo/reference --config demo/coe_config.json \
  --curation-snapshot curation_snapshot.json --curation-decisions decisions.jsonl \
  --output out --overwrite
```

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

## Protected-local enrichment run

Protected processing requires an affirmative data-owner and privacy attestation matching `schemas/protected/1.1.0/data_use_attestation.schema.json`. The example is intentionally unapproved until an authorized person replaces its placeholders. Lexical outputs (dataset synonyms and unmapped candidate terms) are emitted only when the attestation explicitly sets `lexical_output_approved` to true; coding counts, per-system ambiguity counts, and code-pair associations are always aggregate-only.

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

Privacy controls, all recorded in the run report and re-checked by the verifier:

- **Small-cell floor.** Rows whose document count falls below `--min-cell-document-count` (default 3) are suppressed and reported only as suppressed-row counts, so near-unique evidence cannot single out a patient.
- **Scrub filter.** Any lexical text that would leave the process is rejected if it carries long digit runs, contact markers, or excessive length; scrubbed rows are counted, never emitted.
- **Association bounds.** Documents with more codes than `--max-association-codes-per-document` are skipped for association counting, and the pair table is hard-capped.

Before consuming or transferring the result, verify its exact inventory, canonical encoding, artifact and semantic digests, run fingerprint, release identities, code grounding (including that no candidate term is actually groundable), floor compliance, and scrub compliance against the same indexes:

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

Runs and verification accept between one and seven releases; the releases supplied to `verify` must be exactly those the run was bound to.

The protected adapter accepts recursively discovered UTF-8 `.txt` files only. It rejects links, junctions, reparse points, hard links, and nonregular inputs, applies bounded resource limits, reads inputs in place, and atomically writes exactly six files:

- `coding_counts.jsonl` — uniquely grounded coding evidence with frequency counts, across every mention context;
- `ambiguity_counts.jsonl` — per-system ambiguous evidence;
- `context_counts.jsonl` — the mention-context breakdown per code (how much of the evidence is affirmed, negated, family, or historical);
- `lexical_forms.jsonl` — dataset surface forms per code and context (synonym evidence; empty unless lexical output is attested);
- `candidate_terms.jsonl` — ranked frequent unmapped terms with tf-idf salience and their affirmed-mention count (empty unless lexical output is attested);
- `associations.jsonl` — NPMI-scored code co-occurrence pairs, computed from current-clinical mentions only; and
- `run_report.json` with restricted, path-free provenance, software identity, privacy counters, and hashes.

The enriched result exports to interchange formats without any added runtime dependency:

```bash
uv run coe export csv --run /restricted/run/output --output /restricted/run/csv
uv run coe export skos --run /restricted/run/output --output /restricted/run/scheme.ttl
```

The SKOS Turtle carries one `skos:Concept` per coding row (`skos:notation` = the standard code), dataset synonyms as `skos:prefLabel`/`skos:altLabel`, associations as `skos:related`, and each concept's affirmed-mention count as `coe:currentClinicalDocumentCount`. Only current-clinical surface forms become labels: a term seen solely in negated or family context is evidence about the corpus, not a synonym worth publishing. Exported files inherit the restricted classification of their source run.

Raw lexical material exists transiently in Python process memory; Python cannot guarantee secure erasure. Host access, swap, crash-dump, endpoint-protection, encryption, and retention controls therefore remain mandatory.

The current hard ceilings (10,000 files and 100,000,000 input bytes) make this a bounded qualification slice, not a full-corpus production batch engine. Larger approved corpora require a separately tested partition/checkpoint design rather than raising these guards ad hoc.

## Windows and GPU host

The portable deployment is native-Windows-first so it also works on Windows Server hosts where Docker Desktop may not be supported. See [deploy/windows/README-WINDOWS.md](deploy/windows/README-WINDOWS.md). The Windows output verifier delegates semantic verification to `coe protected verify` — there is one verifier implementation, not two.

```bash
uv build
uv run python tools/build_windows_bundle.py \
  --wheel dist/coe_corpus_ontology_enricher-0.4.0a1-py3-none-any.whl \
  --output artifacts/coe-windows-0.4.0a1.zip

uv run python tools/build_reference_bundle.py \
  --reference-set private_build/references \
  --output private_build/coe-private-references.zip
```

The application archive contains no terminology payload or patient data. The second archive is a controlled licensed asset and contains no patient data.

`coe hardware probe --require-nvidia` fails closed if `nvidia-smi` cannot report an NVIDIA GPU. Exact phrase mining and SQLite lookup intentionally run on CPU; this release does not pretend that those operations benefit from CUDA. The GPU stage remains reserved and unimplemented.

## Current boundaries

- Patient inputs and every protected output stay on the authorized host and are treated as restricted data; SKOS/CSV exports of protected runs inherit that classification.
- There is no network, telemetry, automatic acceptance, or public export path. Curation is explicit and human-recorded; nothing is auto-accepted.
- Matching is exact-plus-deterministic-variants; there is no embedding stage.
- Context qualification is a bounded lexical screen: it separates negated, family, and historical mentions but cannot resolve nested or long-range scope, so `current_clinical` counts remain lexical evidence rather than confirmed findings.
- The protected adapter has not been connected to a live database, PDF/DOCX extraction path, or a specific remote patient-data layout.
- The local attestation is an unsigned procedural gate; an authorized reviewer must still verify its corpus scope, purpose, validity window, approval status, and lexical-output decision before each production run.
- CPT source metadata identifies the private Athena export date, not an authoritative CPT edition; publication remains blocked until that edition and destination rights are recorded.
- GPU model, VRAM, driver, Windows edition, data layout, and WSL compatibility must be measured on the target host rather than inferred.

See [SECURITY.md](SECURITY.md), [docs/CONTROLLED_DEPLOYMENT.md](docs/CONTROLLED_DEPLOYMENT.md), and the full [COE design and plan](COE_DESIGN_AND_PLAN.md) for the remaining production gates.
