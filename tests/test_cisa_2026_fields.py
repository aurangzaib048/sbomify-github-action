"""Document fields CISA 2026 and BSI TR-03183-2 v2.1 expect in every SBOM the action writes.

These run the real pipeline (UPLOAD=false) with the generator replaced by one
that writes a fixed document, so what is asserted is the file a user gets.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from sbomify_action import __version__
from sbomify_action.cli.main import build_config, run_pipeline
from sbomify_action.generation import GenerationResult

GENERATOR = {"type": "application", "group": "CycloneDX", "name": "cyclonedx-py", "version": "7.3.0"}
SBOMIFY_ACTION = {"type": "application", "group": "sbomify", "name": "sbomify-action", "version": __version__}

GITHUB_ENV = {
    "GITHUB_ACTIONS": "true",
    "GITHUB_REPOSITORY": "owner/repo",
    "GITHUB_SHA": "a" * 40,
    "GITHUB_REF": "refs/heads/main",
    "GITHUB_SERVER_URL": "https://github.com",
}


def _cdx(spec: str = "1.6", **metadata: object) -> dict:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": spec,
        "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
        "version": 1,
        "metadata": {"timestamp": "2026-10-01T00:00:00Z", **metadata},
        "components": [
            {
                "type": "library",
                "name": "serde",
                "version": "1.0.0",
                "purl": "pkg:cargo/serde@1.0.0",
                "bom-ref": "pkg:cargo/serde@1.0.0",
            }
        ],
    }


def _spdx(**creation_info: object) -> dict:
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "project",
        "documentNamespace": "https://example.com/project",
        "creationInfo": {"created": "2026-10-01T00:00:00Z", "creators": ["Tool: syft-1.42.4"], **creation_info},
        "packages": [
            {
                "SPDXID": "SPDXRef-serde",
                "name": "serde",
                "versionInfo": "1.0.0",
                "downloadLocation": "NOASSERTION",
            }
        ],
    }


def _run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, document: dict, source: str, **overrides: object) -> dict:
    """Run the pipeline on ``document`` as if ``source`` had produced it; return the output."""
    monkeypatch.chdir(tmp_path)
    sbom_format = "cyclonedx" if "bomFormat" in document else "spdx"
    sbom_format = str(overrides.pop("sbom_format", sbom_format))

    def generator(*_args: object, output_file: str, **_kwargs: object) -> GenerationResult:
        Path(output_file).write_text(json.dumps(document), encoding="utf-8")
        return GenerationResult.success_result(
            output_file=output_file, sbom_format=sbom_format, spec_version="1.6", generator_name="fake"
        )

    inputs: dict[str, object] = {}
    if source == "lock_file":
        (tmp_path / "Cargo.lock").write_text("version = 3\n", encoding="utf-8")
        inputs["lock_file"] = "Cargo.lock"
    elif source == "source_dir":
        (tmp_path / "src").mkdir()
        inputs["source_dir"] = "src"
    elif source == "docker_image":
        inputs["docker_image"] = "example/app:1.0"
    elif source == "additional_packages":
        monkeypatch.setenv("ADDITIONAL_PACKAGES", "pkg:pypi/requests@2.32.3")
        inputs["lock_file"] = "none"
    else:
        (tmp_path / "input.json").write_text(json.dumps(document), encoding="utf-8")
        inputs["sbom_file"] = "input.json"

    config = build_config(upload=False, output_file="out.json", sbom_format=sbom_format, **inputs, **overrides)
    with (
        patch("sbomify_action.cli.main.process_lock_file", side_effect=generator),
        patch("sbomify_action.cli.main.generate_sbom", side_effect=generator),
        patch("sbomify_action._generation.chainguard.detect_chainguard_image", return_value=None),
    ):
        run_pipeline(config)
    return json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))


class TestGenerationContext:
    """CISA 2026 "SBOM Generation Context", from what the action was given.

    CycloneDX 1.6 defines the lifecycle phases this maps onto:
      pre-build  -- "information obtained prior to a build process and may
                    contain source files and development artifacts and
                    manifests": a lock file, or a scan of the source tree.
      post-build -- "information obtained after a build process has completed
                    and the resulting component(s) are available for further
                    analysis": a built container image.
    """

    @pytest.mark.parametrize(
        "source,phase",
        [("lock_file", "pre-build"), ("source_dir", "pre-build"), ("docker_image", "post-build")],
    )
    def test_cyclonedx_phase_follows_the_input(self, tmp_path, monkeypatch, source, phase):
        out = _run(tmp_path, monkeypatch, _cdx(), source)
        assert out["metadata"]["lifecycles"] == [{"phase": phase}]

    @pytest.mark.parametrize("source,phase", [("lock_file", "pre-build"), ("docker_image", "post-build")])
    def test_spdx_2_carries_the_phase_in_the_creation_comment(self, tmp_path, monkeypatch, source, phase):
        """SPDX 2.3 has no lifecycle field. creationInfo.comment is where the
        augmentation step already writes a configured phase, and where sbomqs
        looks for generation context in SPDX 2."""
        out = _run(tmp_path, monkeypatch, _spdx(), source)
        assert out["creationInfo"]["comment"] == f"Lifecycle phase: {phase}"

    def test_spdx_2_keeps_an_existing_comment(self, tmp_path, monkeypatch):
        out = _run(tmp_path, monkeypatch, _spdx(comment="Generated in CI"), "lock_file")
        assert out["creationInfo"]["comment"] == "Generated in CI | Lifecycle phase: pre-build"

    def test_a_phase_the_generator_declared_is_kept(self, tmp_path, monkeypatch):
        """cdxgen writes its own lifecycles; it knows whether it installed anything."""
        out = _run(tmp_path, monkeypatch, _cdx(lifecycles=[{"phase": "build"}]), "lock_file")
        assert out["metadata"]["lifecycles"] == [{"phase": "build"}]

    def test_cyclonedx_before_1_5_has_no_lifecycles_field(self, tmp_path, monkeypatch):
        out = _run(tmp_path, monkeypatch, _cdx("1.4"), "lock_file", spec_version="1.4")
        assert "lifecycles" not in out["metadata"]

    def test_a_supplied_sbom_is_not_given_a_phase(self, tmp_path, monkeypatch):
        """Nothing says how someone else's SBOM was produced, so nothing is claimed."""
        out = _run(tmp_path, monkeypatch, _cdx(), "sbom_file")
        assert "lifecycles" not in out["metadata"]

    def test_a_supplied_sbom_is_not_given_a_phase_by_augmentation_in_ci(self, tmp_path, monkeypatch):
        """Running in CI says where the action ran, not what was scanned. The CI
        provider used to stamp pre-build on every document, a user's SBOM_FILE
        of a built image included."""
        for name, value in GITHUB_ENV.items():
            monkeypatch.setenv(name, value)
        out = _run(tmp_path, monkeypatch, _cdx(), "sbom_file", augment=True)
        assert "lifecycles" not in out["metadata"]

    def test_a_configured_phase_wins_over_the_derived_one(self, tmp_path, monkeypatch):
        (tmp_path / "sbomify.json").write_text(json.dumps({"lifecycle_phase": "build"}), encoding="utf-8")
        out = _run(tmp_path, monkeypatch, _cdx(), "lock_file", augment=True)
        assert out["metadata"]["lifecycles"] == [{"phase": "build"}]


class TestToolNameAndVersion:
    """CISA 2026 "SBOM Tool Name" and "SBOM Tool Version".

    Both the generator that ran and sbomify-action, which ran it and rewrote
    its output, are named with versions. sbomify-action used to be listed only
    when AUGMENT was on.
    """

    def test_cyclonedx_lists_the_generator_and_sbomify_action(self, tmp_path, monkeypatch):
        out = _run(tmp_path, monkeypatch, _cdx(tools={"components": [GENERATOR]}), "lock_file")
        assert out["metadata"]["tools"]["components"] == [GENERATOR, SBOMIFY_ACTION]

    def test_cyclonedx_1_4_uses_the_legacy_tool_array(self, tmp_path, monkeypatch):
        cargo = {"vendor": "CycloneDX", "name": "cargo-cyclonedx", "version": "0.5.7"}
        out = _run(tmp_path, monkeypatch, _cdx("1.4", tools=[cargo]), "lock_file", spec_version="1.4")
        assert out["metadata"]["tools"] == [
            cargo,
            {"vendor": "sbomify", "name": "sbomify-action", "version": __version__},
        ]

    def test_a_document_sbomify_action_wrote_itself_names_it(self, tmp_path, monkeypatch):
        """gradle.lockfile is read by the action's own code, which listed no tool at all."""
        out = _run(tmp_path, monkeypatch, _cdx(), "lock_file")
        assert out["metadata"]["tools"] == {"components": [SBOMIFY_ACTION]}

    def test_sbomify_action_is_not_listed_twice(self, tmp_path, monkeypatch):
        """Augmentation lists it as a service named "sbomify action"."""
        listed = {"services": [{"group": "sbomify", "name": "sbomify action", "version": __version__}]}
        out = _run(tmp_path, monkeypatch, _cdx(tools=listed), "lock_file")
        assert out["metadata"]["tools"] == listed

    def test_spdx_2_creators_list_the_generator_and_sbomify_action(self, tmp_path, monkeypatch):
        out = _run(tmp_path, monkeypatch, _spdx(), "lock_file")
        assert out["creationInfo"]["creators"] == ["Tool: syft-1.42.4", f"Tool: sbomify-action-{__version__}"]

    def test_a_supplied_sbom_keeps_its_own_tools(self, tmp_path, monkeypatch):
        out = _run(tmp_path, monkeypatch, _cdx(tools={"components": [GENERATOR]}), "sbom_file")
        assert out["metadata"]["tools"] == {"components": [GENERATOR]}

    def test_additional_packages_only_cyclonedx_names_sbomify_action(self, tmp_path, monkeypatch):
        out = _run(tmp_path, monkeypatch, {}, "additional_packages", sbom_format="cyclonedx")
        assert SBOMIFY_ACTION in out["metadata"]["tools"]["components"]

    def test_additional_packages_only_spdx_2_names_the_version(self, tmp_path, monkeypatch):
        out = _run(tmp_path, monkeypatch, {}, "additional_packages", sbom_format="spdx")
        tools = [c for c in out["creationInfo"]["creators"] if c.startswith("Tool:")]
        assert tools == [f"Tool: sbomify-action-{__version__}"]

    def test_additional_packages_only_spdx_3_names_the_version(self, tmp_path, monkeypatch):
        out = _run(tmp_path, monkeypatch, {}, "additional_packages", sbom_format="spdx", spec_version="3.0.1")
        tools = [e["name"] for e in out["@graph"] if e.get("type") == "Tool"]
        assert tools == [f"sbomify-action-{__version__}"]


class TestSupplierFromPublisher:
    """sbomqs never reads CycloneDX ``publisher``; its NTIA 2021, Interlynk and
    FSCT supplier checks read ``supplier``. Enrichment named some components'
    publisher and left the supplier empty."""

    @staticmethod
    def _enrich(tmp_path: Path, components: list[dict]) -> list[dict]:
        from unittest.mock import Mock

        from sbomify_action.enrichment import clear_cache, enrich_sbom

        document = _cdx()
        document["components"] = components
        (tmp_path / "in.json").write_text(json.dumps(document), encoding="utf-8")
        clear_cache()
        with patch("requests.Session.get", return_value=Mock(status_code=404)):
            enrich_sbom(str(tmp_path / "in.json"), str(tmp_path / "out.json"), validate=False)
        return json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))["components"]

    def test_the_distribution_behind_an_os_component_is_its_supplier(self, tmp_path):
        os_component = {"type": "operating-system", "name": "alpine", "version": "3.20.10", "bom-ref": "os"}
        library = {"type": "library", "name": "x", "version": "1", "purl": "pkg:generic/x@1", "bom-ref": "x"}
        out = {c["bom-ref"]: c for c in self._enrich(tmp_path, [os_component, library])}
        assert out["os"]["publisher"] == "Alpine Linux"
        assert out["os"]["supplier"] == {"name": "Alpine Linux"}

    def test_a_publisher_with_no_supplier_becomes_the_supplier(self, tmp_path):
        component = {
            "type": "library",
            "name": "x",
            "version": "1",
            "purl": "pkg:generic/x@1",
            "bom-ref": "x",
            "publisher": "Jane Maintainer",
        }
        assert self._enrich(tmp_path, [component])[0]["supplier"] == {"name": "Jane Maintainer"}

    def test_an_existing_supplier_is_never_overwritten(self, tmp_path):
        component = {
            "type": "library",
            "name": "x",
            "version": "1",
            "purl": "pkg:generic/x@1",
            "bom-ref": "x",
            "publisher": "Jane Maintainer",
            "supplier": {"name": "Acme Corp"},
        }
        assert self._enrich(tmp_path, [component])[0]["supplier"] == {"name": "Acme Corp"}
