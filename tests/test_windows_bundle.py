from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT = Path(__file__).resolve().parents[1]
WINDOWS = PROJECT / "deploy" / "windows"
DOCKER = WINDOWS / "docker"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_windows_bundle_contains_required_native_and_container_surfaces() -> None:
    required = {
        "Build-PortableBundle.ps1",
        "Collect-HostFacts.ps1",
        "Common.ps1",
        "Inspect-InputLayout.ps1",
        "Install-Native.ps1",
        "Invoke-WslDocker.ps1",
        "Preflight-ProtectedRun.ps1",
        "README-WINDOWS.md",
        "Run-Coe.ps1",
        "Verify-Run.ps1",
        "config/model_manifest.example.json",
        "config/protected_data_attestation.example.json",
        "config/protected_run.example.json",
        "config/terminology_entitlement.example.json",
        "docker/Dockerfile.gpu",
        "docker/compose.gpu.yaml",
        "docker/run-protected.sh",
        "docker/validate_attestation.py",
    }
    actual = {path.relative_to(WINDOWS).as_posix() for path in WINDOWS.rglob("*") if path.is_file()}
    assert required <= actual


def test_templates_are_safe_by_default_and_contain_no_payload_paths() -> None:
    attestation = json.loads(_read(WINDOWS / "config/protected_data_attestation.example.json"))
    entitlement = json.loads(_read(WINDOWS / "config/terminology_entitlement.example.json"))
    run_profile = json.loads(_read(WINDOWS / "config/protected_run.example.json"))
    model = json.loads(_read(WINDOWS / "config/model_manifest.example.json"))

    assert attestation["profile"] == "protected_phi_local"
    assert attestation["approved"] is False
    assert attestation["output_classification"] == "protected_aggregate"
    assert attestation["approval_refs"]["data_owner"].startswith("REPLACE-WITH")
    assert set(attestation) == {
        "approval_refs",
        "approved",
        "attestation_schema_version",
        "output_classification",
        "profile",
        "retention_policy_id",
    }
    assert entitlement["controlled_uses"]["analysis_use_permitted"] is False
    assert entitlement["assertion_ref"].startswith("REPLACE-WITH")
    assert len(entitlement["terminologies"]) == 7
    assert run_profile["network_policy"] == "dedicated-python-outbound-block-required"
    assert run_profile["exact_matching"]["device"] == "cpu"
    assert run_profile["semantic_matching"]["enabled"] is False
    assert model["semantic_stage_enabled"] is False
    assert model["weights_sha256"] is None


def test_host_facts_collection_omits_identifying_and_patient_data_queries() -> None:
    script = _read(WINDOWS / "Collect-HostFacts.ps1").casefold()
    forbidden = (
        "win32_networkadapter",
        "win32_networkadapterconfiguration",
        "ipaddress",
        "serialnumber",
        "get-netipconfiguration",
        "get-netipaddress",
        "whoami",
        "$env:computername",
        "$env:username",
        "get-childitem",
        "get-content",
    )
    assert not any(term in script for term in forbidden)
    assert "patient_paths_collected = $false" in script
    assert "identifiers_omitted = $true" in script
    assert "--query-gpu=name,memory.total,driver_version" in script


def test_input_layout_inspector_is_metadata_only_and_does_not_follow_reparse_points() -> None:
    script = _read(WINDOWS / "Inspect-InputLayout.ps1").casefold()
    assert "get-content" not in script
    assert "readalltext" not in script
    assert "opentext" not in script
    assert "-followsymlink" not in script
    assert "fileattributes]::reparsepoint" in script
    assert "$allowedextensions" in script
    assert 'extension = "<other>"' in script
    assert "total_files" in script
    assert "total_bytes" in script
    assert "reparse_point_count" in script
    assert "extension_counts" in script


def test_native_run_requires_attestation_acl_integrity_and_offline_controls() -> None:
    preflight = _read(WINDOWS / "Preflight-ProtectedRun.ps1")
    runner = _read(WINDOWS / "Run-Coe.ps1")
    installer = _read(WINDOWS / "Install-Native.ps1")
    common = _read(WINDOWS / "Common.ps1")
    container_runner = _read(WINDOWS / "Invoke-WslDocker.ps1")

    assert "attestation_schema_version" in preflight
    assert "protected_phi_local" in preflight
    assert "protected_aggregate" in preflight
    assert '"reference", "verify-set"' in preflight
    assert "required seven terminology indexes" in preflight
    assert "approved plaintext extraction adapter" in preflight
    assert "Assert-CoeReadOnlyAcl" in preflight
    assert "Test-CoeOutboundBlock" in preflight
    assert "ContainerReadOnlyMounts" in preflight
    assert "Assert-CoeLocalFixedPath -Path $resolvedCorpus" in preflight
    assert "Assert-CoeLocalFixedPath -Path $resolvedReferenceSet" in preflight
    assert "Assert-CoeLocalFixedPath -Path $resolvedAttestation" in preflight
    assert "Assert-CoeLocalFixedPath -Path $resolvedOutput" in preflight
    assert "Get-CoeBoundedTreeInventory" in preflight
    assert "[ValidateRange(1, 10000)][Int64]$MaxFiles = 10000" in preflight
    assert "[ValidateRange(1, 100000000)][Int64]$MaxTotalBytes = 100000000" in preflight
    assert "$referenceInventory.file_count -ne 10" in preflight
    assert "DriveType]::Fixed" in common
    assert "UNC paths are forbidden" in common
    assert "mapped network drives are forbidden" in common
    assert "Get-CoeTreeDigest" in runner
    assert "[Int64]$MaxFiles" in common
    assert "[Int64]$MaxBytes" in common
    assert "[Int64]$MaxWalkEntries" in common
    assert "EnumerateFileSystemEntries" in common
    assert "exceeds the approved filesystem-entry limit" in common
    assert "-MaxFiles $corpusDigestMaxFiles" in runner
    assert "-MaxBytes $corpusDigestMaxBytes" in runner
    assert "-MaxWalkEntries 50000" in runner
    assert "-MaxFiles 10" in runner
    assert "-MaxBytes 68719476736" in runner
    assert "MaxFiles = $corpusDigestMaxFiles" in runner
    assert "MaxTotalBytes = $corpusDigestMaxBytes" in runner
    assert "-MaxFiles $corpusDigestMaxFiles" in container_runner
    assert "-MaxBytes $corpusDigestMaxBytes" in container_runner
    assert "-MaxFiles 10" in container_runner
    assert "MaxFiles = $corpusDigestMaxFiles" in container_runner
    assert '"protected",' in runner and '"run",' in runner
    assert '"--corpus"' in runner
    assert '"--attestation"' in runner
    assert '$arguments.Add("--index")' in runner
    assert "--max-total-bytes" in runner
    assert "HF_HUB_OFFLINE" in runner
    assert "TRANSFORMERS_OFFLINE" in runner
    assert "HTTP_PROXY" in runner
    assert "Verify-Run.ps1" in runner
    assert "--no-index" in installer
    assert "checksums.sha256" in installer
    assert "New-NetFirewallRule" in installer
    assert "Get-CoeSafeError" in common
    assert "Get-CoeSafeError -Exception" in preflight
    assert "Get-CoeSafeError -Exception" in runner
    assert "Get-CoeSafeError -Exception" in installer


def test_portable_builder_uses_allowlist_and_declares_no_protected_payloads() -> None:
    builder = _read(WINDOWS / "Build-PortableBundle.ps1")
    assert "$deploymentFiles" in builder
    assert '"Inspect-InputLayout.ps1"' in builder
    assert "contains_patient_data = $false" in builder
    assert "contains_terminology_payloads = $false" in builder
    assert "contains_model_weights = $false" in builder
    assert "checksums.sha256" in builder


def test_bundle_install_chain_binds_wheel_package_version_path_and_hash() -> None:
    common = _read(WINDOWS / "Common.ps1")
    builder = _read(WINDOWS / "Build-PortableBundle.ps1")
    installer = _read(WINDOWS / "Install-Native.ps1")

    assert "Get-CoeApplicationWheelIdentity" in common
    assert "IO.Compression.ZipFile" in common
    assert ".dist-info/METADATA" in common
    assert "coe_corpus_ontology_enricher-" in common
    assert "-py3-none-any\\.whl" in common
    assert "regular, non-reparse file" in common
    assert 'application_package = "coe-corpus-ontology-enricher"' not in builder
    assert "application_package = $copiedWheelIdentity.application_package" in builder
    assert "application_version = $copiedWheelIdentity.application_version" in builder
    assert 'path = "app/" + $copiedWheelIdentity.filename' in builder
    assert 'portable_bundle_schema_version = "1.1.0"' in builder
    assert "Get-BundleApplicationContract" in installer
    assert "runtime_manifest.json" in installer
    assert "bundle-manifest.json" in installer
    assert "python_runtime_manifest_1.0.0" in installer
    assert "powershell_bundle_manifest_1.1.0" in installer
    assert '-Expected @("distribution", "path", "sha256", "version")' in installer
    assert '$manifest.wheel.distribution -cne "coe-corpus-ontology-enricher"' in installer
    assert "$manifest.wheel.version -cne $manifest.application_version" in installer
    assert "wheel_sha256" in installer
    assert "importlib.metadata" in installer
    assert "installedVersion -cne $applicationContract.application_version" in installer
    assert 'publishedVersion -cne ("coe " + $applicationContract.application_version)' in installer
    assert "Test-BundleChecksums -Root $temporary" in installer


def test_bundle_and_install_replacement_targets_are_bidirectionally_disjoint() -> None:
    builder = _read(WINDOWS / "Build-PortableBundle.ps1")
    installer = _read(WINDOWS / "Install-Native.ps1")

    assert "Test-CoePathWithin -Path $output -Root $sourceRoot" in builder
    assert "Test-CoePathWithin -Path $sourceRoot -Root $output" in builder
    assert "must be disjoint from every packaging input" in builder
    assert "Test-CoePathWithin -Path $install -Root $bundle" in installer
    assert "Test-CoePathWithin -Path $bundle -Root $install" in installer
    assert "must be disjoint" in installer
    assert "$_.Exception.Message" not in builder
    assert "$_.Exception.Message" not in installer


def test_compose_enforces_no_network_nonroot_readonly_inputs_and_restricted_output() -> None:
    compose = _read(DOCKER / "compose.gpu.yaml")
    assert 'network_mode: "none"' in compose
    assert "read_only: true" in compose
    assert 'user: "65532:65532"' in compose
    assert "driver: nvidia" in compose
    assert "count: all" in compose
    assert "- gpu" in compose
    assert "cap_drop:" in compose and "- ALL" in compose
    assert "no-new-privileges:true" in compose
    assert "pull_policy: never" in compose
    assert "ports:" not in compose
    for target in ("/data/corpus", "/data/references", "/control/data_use_attestation.json"):
        assert target in compose
    for forbidden in ("/data/snapshot", "/control/coe_config.json", "/models"):
        assert forbidden not in compose
    assert compose.count("read_only: true") >= 4
    assert "target: /data/output" in compose
    assert "read_only: false" in compose
    assert "COE_OUTPUT_STAGING_PATH" in compose
    assert "COE_OUTPUT_PATH" not in compose
    assert "COE_OUTPUT_NAME" not in compose
    assert "COE_OVERWRITE" not in compose
    assert compose.count("read_only: false") == 1


def test_container_wrapper_pins_image_id_and_atomically_publishes_staged_output() -> None:
    wrapper = _read(WINDOWS / "Invoke-WslDocker.ps1")

    assert '$expectedImageTag = "coe-protected-local:0.2.0a1"' in wrapper
    assert 'docker.exe image inspect --format "{{.Id}}"' in wrapper
    assert "^sha256:[0-9a-f]{64}$" in wrapper
    assert "$env:COE_IMAGE_NAME = $containerImageId" in wrapper
    assert "immutable COE container image ID could not be reverified after execution" in wrapper
    assert "container_image_id = [string]$containerImageId" in wrapper
    assert '"COE_OUTPUT_STAGING_PATH"' in wrapper
    assert "$env:COE_OUTPUT_STAGING_PATH = $stagingRoot" in wrapper
    assert 'Join-Path $stagingRoot "result"' in wrapper
    assert "-OutputPath $stagedOutput" in wrapper
    assert "[IO.Directory]::Move($stagedOutput, $output)" in wrapper
    assert "[IO.Directory]::Move($backupPath, $output)" in wrapper
    assert "Remove-CoeOwnedStagingDirectory" in wrapper
    assert "Assert-CoeBidirectionalDisjoint" in wrapper
    assert "unique_one_run_staging_then_atomic_publish" in wrapper
    assert "$env:COE_OUTPUT_PATH" not in wrapper


def test_dockerfile_installs_only_code_and_offline_wheels() -> None:
    dockerfile = _read(DOCKER / "Dockerfile.gpu")
    assert not dockerfile.startswith("# syntax=")
    assert "PIP_NO_INDEX=1" in dockerfile
    assert "HF_HUB_OFFLINE=1" in dockerfile
    assert "USER 65532:65532" in dockerfile
    assert "--no-index" in dockerfile
    for forbidden in ("COPY snapshot", "COPY references", "COPY models", "COPY patient", "ADD http"):
        assert forbidden not in dockerfile


def _attestation() -> dict[str, object]:
    return {
        "attestation_schema_version": "1.0.0",
        "profile": "protected_phi_local",
        "approved": True,
        "approval_refs": {
            "data_owner": "DATA-OWNER-APPROVAL-001",
            "privacy": "PRIVACY-APPROVAL-001",
            "security": "SECURITY-APPROVAL-001",
        },
        "retention_policy_id": "RETENTION-POLICY-001",
        "output_classification": "protected_aggregate",
    }


def test_container_attestation_validator_accepts_explicit_protected_approval(tmp_path: Path) -> None:
    attestation = _attestation()
    attestation_path = tmp_path / "attestation.json"
    attestation_path.write_text(json.dumps(attestation), encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            str(DOCKER / "validate_attestation.py"),
            "--attestation",
            str(attestation_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["status"] == "passed"


def test_container_attestation_validator_fails_closed_when_unapproved(tmp_path: Path) -> None:
    attestation = _attestation()
    attestation["approved"] = False
    attestation_path = tmp_path / "attestation.json"
    attestation_path.write_text(json.dumps(attestation), encoding="utf-8")
    result = subprocess.run(
        [
            sys.executable,
            str(DOCKER / "validate_attestation.py"),
            "--attestation",
            str(attestation_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 4
    error = json.loads(result.stderr)
    assert error["status"] == "failed"
    assert str(tmp_path) not in result.stderr


def test_container_entrypoint_uses_protected_cli_and_all_seven_indexes() -> None:
    script = _read(DOCKER / "run-protected.sh")
    assert "-m coe protected run" in script
    assert "--corpus" in script
    assert "--attestation" in script
    assert "arguments+=(--index" in script
    assert 'output="$output_root/result"' in script
    assert 'arguments+=(--output "$output")' in script
    assert "one-run output staging directory is not empty" in script
    assert "cpt hcpcs icd10cm icd10pcs loinc rxnorm snomed" in script
    assert "-m coe reference verify-set" in script
    assert "COE_OUTPUT_NAME" not in script
    assert "COE_OVERWRITE" not in script
    for forbidden in ("preflight snapshot", "terminology_release_manifest.json", "--config"):
        assert forbidden not in script


def test_output_verifier_streams_and_enforces_aggregate_only_schema() -> None:
    verifier = _read(WINDOWS / "Verify-Run.ps1")
    assert "IO.StreamReader" in verifier
    assert "ReadAllText" not in verifier
    assert "protected-local-1.0.0" in verifier
    assert "protected_aggregate" in verifier
    assert "coding_counts.jsonl" in verifier
    assert "ambiguity_counts.jsonl" in verifier
    assert "unsupported field" in verifier
    assert "ReferenceSetPath" in verifier
    assert "PythonExe" in verifier
    assert "reference verify-set" in verifier
    assert "verify_licensed_index_set" in verifier
    assert "code_catalog" in verifier
    assert '"protected", "verify", "--output", $output' in verifier
    assert "protected-output-verification-1.0.0" in verifier
    assert "trusted_core_verification_schema_version" in verifier
    assert "SetEquals($referenceIdentities)" in verifier
    assert "maximumLineCharacters = 16384" in verifier
    assert "reportItem.Length -gt 1048576" in verifier
    assert "Assert-CoeBoundedInteger" in verifier
    assert "$expectedLimitations" in verifier
    assert "limitations do not match the approved contract" in verifier
    assert "max_unique_phrases = 1000000" in verifier


def test_container_entrypoint_has_valid_bash_syntax() -> None:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is unavailable")
    result = subprocess.run(
        [bash, "-n", str(DOCKER / "run-protected.sh")],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="PowerShell parser is unavailable")
def test_powershell_scripts_parse() -> None:
    parser = shutil.which("pwsh")
    assert parser is not None
    for script in WINDOWS.glob("*.ps1"):
        command = (
            "$tokens=$null;$errors=$null;"
            "$path=[Environment]::GetEnvironmentVariable('COE_PS_PARSE_TARGET','Process');"
            "if([string]::IsNullOrWhiteSpace($path)){Write-Error 'Missing parser target';exit 2};"
            "[System.Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)|Out-Null;"
            "if($errors.Count -gt 0){$errors|ForEach-Object{$_.Message};exit 1}"
        )
        result = subprocess.run(
            [parser, "-NoProfile", "-NonInteractive", "-Command", command],
            check=False,
            capture_output=True,
            text=True,
            env={**os.environ, "COE_PS_PARSE_TARGET": str(script.resolve())},
        )
        assert result.returncode == 0, f"{script.name}: {result.stdout} {result.stderr}"
