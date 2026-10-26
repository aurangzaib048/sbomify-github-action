"""PURL clean-up reaches the output whatever ENRICH is set to."""

from __future__ import annotations

import json

from sbomify_action.cli.main import build_config, run_pipeline

FORMULATION = [{"bom-ref": "build", "components": [{"type": "application", "name": "builder"}]}]


def test_file_purl_is_cleared_with_enrich_off(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "input.cdx.json"
    src.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
                "version": 1,
                "metadata": {"component": {"type": "application", "name": "app", "bom-ref": "app"}},
                "components": [
                    {"type": "library", "name": "local", "bom-ref": "local", "purl": "pkg:npm/local@file:../local"},
                    {"type": "library", "name": "request", "bom-ref": "req", "purl": "pkg:npm/%40root/request@1.9.2"},
                ],
                "formulation": FORMULATION,
            }
        )
    )

    run_pipeline(build_config(sbom_file=str(src), upload=False, enrich=False, output_file="out.json"))

    out = json.loads((tmp_path / "out.json").read_text())
    assert {c["name"]: c.get("purl") for c in out["components"]} == {
        "local": None,
        "request": "pkg:npm/%40root/request@1.9.2",
    }
    # The rest of the document is left as it was, including fields the
    # CycloneDX library does not model and would drop on a round trip.
    assert out["formulation"] == FORMULATION
