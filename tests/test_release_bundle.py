from __future__ import annotations

import base64
import hashlib
import importlib.util
import os
import zipfile
from pathlib import Path

import pytest


def _builder_module(project: Path):
    path = project / "tools" / "build_windows_bundle.py"
    spec = importlib.util.spec_from_file_location("build_windows_bundle", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _reference_builder_module(project: Path):
    path = project / "tools" / "build_reference_bundle.py"
    spec = importlib.util.spec_from_file_location("build_reference_bundle", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _fixture_project(tmp_path: Path) -> tuple[Path, Path]:
    project = tmp_path / "project"
    (project / "deploy/windows/config").mkdir(parents=True)
    (project / "deploy/windows/README-WINDOWS.md").write_text("safe\n", encoding="utf-8")
    (project / "specs").mkdir()
    (project / "specs/licensed_terminologies.json").write_text("{}\n", encoding="utf-8")
    (project / "governance").mkdir()
    (project / "governance/terminology_entitlement_assertion.json").write_text("{}\n", encoding="utf-8")
    (project / "docs").mkdir()
    (project / "docs/CONTROLLED_DEPLOYMENT.md").write_text("safe\n", encoding="utf-8")
    (project / "SECURITY.md").write_text("safe\n", encoding="utf-8")
    wheel = tmp_path / "coe_corpus_ontology_enricher-0.2.0a1-py3-none-any.whl"
    dist_info = "coe_corpus_ontology_enricher-0.2.0a1.dist-info"
    wheel_members = {
        "coe/__init__.py": b'__version__ = "0.2.0a1"\n',
        f"{dist_info}/METADATA": (b"Metadata-Version: 2.2\nName: coe-corpus-ontology-enricher\nVersion: 0.2.0a1\n\n"),
        f"{dist_info}/WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        f"{dist_info}/entry_points.txt": b"[console_scripts]\ncoe = coe.cli:main\n",
        f"{dist_info}/top_level.txt": b"coe\n",
    }
    record_name = f"{dist_info}/RECORD"
    record_rows = []
    for name, payload in sorted(wheel_members.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode("ascii")
        record_rows.append(f"{name},sha256={digest},{len(payload)}")
    record_rows.append(f"{record_name},,")
    wheel_members[record_name] = ("\n".join(record_rows) + "\n").encode("utf-8")
    with zipfile.ZipFile(wheel, "w") as archive:
        for name, payload in wheel_members.items():
            archive.writestr(name, payload)
    return project, wheel


def test_bundle_is_deterministic_and_excludes_controlled_payloads(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    builder = _builder_module(project_root)
    project, wheel = _fixture_project(tmp_path)
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"
    builder.build_windows_bundle(project_root=project, wheel=wheel, output=first)
    builder.build_windows_bundle(project_root=project, wheel=wheel, output=second)
    assert hashlib.sha256(first.read_bytes()).digest() == hashlib.sha256(second.read_bytes()).digest()
    with zipfile.ZipFile(first) as archive:
        names = archive.namelist()
        assert any(name.endswith("checksums.sha256") for name in names)
        assert any(name.endswith("runtime_manifest.json") for name in names)
        lowered = "\n".join(names).casefold()
        assert "patientdata" not in lowered
        assert ".rdp" not in lowered
        assert "/raw/" not in lowered


def test_bundle_refuses_secret_like_deployment_member(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    builder = _builder_module(project_root)
    project, wheel = _fixture_project(tmp_path)
    (project / "deploy/windows/server.key").write_text("secret", encoding="utf-8")
    with pytest.raises(ValueError, match="prohibited bundle member"):
        builder.build_windows_bundle(project_root=project, wheel=wheel, output=tmp_path / "unsafe.zip")


def test_bundle_refuses_mislabeled_or_workstation_contaminated_wheel(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    builder = _builder_module(project_root)
    project, wheel = _fixture_project(tmp_path)
    wrong_name = wheel.with_name("coe_corpus_ontology_enricher-0.1.0-py3-none-any.whl")
    wrong_name.write_bytes(wheel.read_bytes())
    with pytest.raises(ValueError, match="exact .* release artifact"):
        builder.build_windows_bundle(project_root=project, wheel=wrong_name, output=tmp_path / "wrong.zip")

    with zipfile.ZipFile(wheel, "a") as archive:
        archive.writestr(
            "coe_corpus_ontology_enricher-0.2.0a1.data/data/share/coe/workstation_note.md",
            "/Users/example/private/source",
        )
    with pytest.raises(ValueError, match="prohibited workstation"):
        builder.build_windows_bundle(project_root=project, wheel=wheel, output=tmp_path / "contaminated.zip")


def test_bundle_refuses_workstation_path_in_deployment_content(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    builder = _builder_module(project_root)
    project, wheel = _fixture_project(tmp_path)
    (project / "deploy/windows/README-WINDOWS.md").write_text("/Users/example/private/source\n", encoding="utf-8")
    with pytest.raises(ValueError, match="prohibited workstation"):
        builder.build_windows_bundle(project_root=project, wheel=wheel, output=tmp_path / "unsafe-content.zip")


def test_bundle_refuses_hard_linked_deployment_member(tmp_path: Path) -> None:
    project_root = Path(__file__).resolve().parents[1]
    builder = _builder_module(project_root)
    project, wheel = _fixture_project(tmp_path)
    external = tmp_path / "external.ps1"
    external.write_text("Write-Output safe\n", encoding="utf-8")
    try:
        os.link(external, project / "deploy/windows/hard-linked.ps1")
    except OSError:
        pytest.skip("Hard links are unavailable in this environment")
    with pytest.raises(ValueError, match="hard-linked deployment"):
        builder.build_windows_bundle(project_root=project, wheel=wheel, output=tmp_path / "hard-link.zip")


def test_bundle_outputs_cannot_be_nested_inside_packaging_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project_root = Path(__file__).resolve().parents[1]
    builder = _builder_module(project_root)
    project, wheel = _fixture_project(tmp_path)
    with pytest.raises(ValueError, match="inside the deployment"):
        builder.build_windows_bundle(
            project_root=project,
            wheel=wheel,
            output=project / "deploy/windows/nested.zip",
        )

    reference_builder = _reference_builder_module(project_root)
    reference_set = tmp_path / "reference-set"
    reference_set.mkdir()
    monkeypatch.setattr(
        reference_builder,
        "verify_licensed_index_set",
        lambda _: {"set_content_sha256": "a" * 64},
    )
    with pytest.raises(ValueError, match="inside the reference set"):
        reference_builder.build_reference_bundle(
            reference_set=reference_set,
            output=reference_set / "nested.zip",
        )


def test_reference_bundle_reverifies_the_copied_set_before_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project_root = Path(__file__).resolve().parents[1]
    builder = _reference_builder_module(project_root)
    source = tmp_path / "references"
    source.mkdir()
    for name, payload in {
        "checksums.sha256": b"fixture\n",
        "cpt.sqlite3": b"sqlite fixture",
        "reference_set_manifest.json": b"{}\n",
        "terminology_entitlement_assertion.json": b"{}\n",
    }.items():
        (source / name).write_bytes(payload)
    manifest = {"set_content_sha256": "a" * 64}
    verified_paths: list[Path] = []

    def verify(path: Path) -> dict[str, str]:
        verified_paths.append(path)
        assert {item.name for item in path.iterdir()} == {item.name for item in source.iterdir()}
        return manifest

    monkeypatch.setattr(builder, "verify_licensed_index_set", verify)
    output = tmp_path / "private-references.zip"
    builder.build_reference_bundle(reference_set=source, output=output)
    assert verified_paths[0] == source
    assert verified_paths[1].name == "references"
    with zipfile.ZipFile(output) as archive:
        names = archive.namelist()
        assert any(name.endswith("references/cpt.sqlite3") for name in names)
        assert not any(name.endswith((".csv", ".rdp", ".cookie")) for name in names)


def test_reference_bundle_fails_if_the_copied_set_differs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    project_root = Path(__file__).resolve().parents[1]
    builder = _reference_builder_module(project_root)
    source = tmp_path / "references"
    source.mkdir()
    (source / "reference_set_manifest.json").write_text("{}\n", encoding="utf-8")
    calls = 0

    def verify(_: Path) -> dict[str, str]:
        nonlocal calls
        calls += 1
        return {"set_content_sha256": ("a" if calls == 1 else "b") * 64}

    monkeypatch.setattr(builder, "verify_licensed_index_set", verify)
    output = tmp_path / "private-references.zip"
    with pytest.raises(ValueError, match="changed while"):
        builder.build_reference_bundle(reference_set=source, output=output)
    assert not output.exists()
