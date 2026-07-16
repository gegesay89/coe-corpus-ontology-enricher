#!/usr/bin/env bash
set -euo pipefail
umask 077

corpus=/data/corpus
reference_set=/data/references
attestation=/control/data_use_attestation.json
output_root=/data/output
output="$output_root/result"

fail() {
  printf '%s\n' "{\"status\":\"failed\",\"safe_error\":\"$1\"}" >&2
  exit 4
}

if [[ ! -d "$corpus" || ! -f "$reference_set/reference_set_manifest.json" || ! -f "$attestation" ]]; then
  fail "A required protected-run input is missing."
fi
shopt -s nullglob dotglob
staging_entries=("$output_root"/*)
shopt -u nullglob dotglob
if (( ${#staging_entries[@]} != 0 )); then
  fail "The one-run output staging directory is not empty."
fi

/opt/coe/bin/python /opt/coe-deploy/validate_attestation.py \
  --attestation "$attestation" >/dev/null
/opt/coe/bin/python -m coe reference verify-set "$reference_set" >/dev/null

terminologies=(cpt hcpcs icd10cm icd10pcs loinc rxnorm snomed)
indexes=()
for terminology in "${terminologies[@]}"; do
  index="$reference_set/$terminology.sqlite3"
  if [[ ! -f "$index" ]]; then
    fail "The verified reference set does not contain all seven terminology indexes."
  fi
  indexes+=("$index")
done

arguments=(
  -m coe protected run
  --corpus "$corpus"
  --attestation "$attestation"
)
for index in "${indexes[@]}"; do
  arguments+=(--index "$index")
done
arguments+=(--output "$output")

add_optional_limit() {
  local environment_name="$1"
  local option_name="$2"
  local value="${!environment_name:-}"
  if [[ -n "$value" ]]; then
    arguments+=("$option_name" "$value")
  fi
}

add_optional_limit COE_MAX_FILES --max-files
add_optional_limit COE_MAX_TOTAL_BYTES --max-total-bytes
add_optional_limit COE_MAX_TOTAL_TOKENS --max-total-tokens
add_optional_limit COE_MAX_TOTAL_NGRAMS --max-total-ngrams
add_optional_limit COE_MAX_NGRAM_TOKENS --max-ngram-tokens
add_optional_limit COE_MAX_CANDIDATES_PER_PHRASE_SYSTEM --max-candidates-per-phrase-system

# Exact matching remains CPU-only. This switch only requires NVIDIA visibility
# for deployment qualification; it does not move exact matching onto the GPU.
if [[ "${COE_REQUIRE_GPU:-0}" == "1" ]]; then
  arguments+=(--require-nvidia)
fi
exec /opt/coe/bin/python "${arguments[@]}"
