"""COMPONENT_NAME, COMPONENT_VERSION and COMPONENT_PURL belong on the package
an SPDX document describes, never on ``packages[0]``.

syft lists a lock file's dependencies first and the package the document
describes last. Writing the overrides to the first package renamed ``arrow``
to "sbomify Action" in this repository's own SPDX SBOM and handed it the
action's PURL, while the package the document actually describes kept its old
identity.
"""

import json
import sys
from pathlib import Path

import pytest

from sbomify_action._generation.result import GenerationResult
from sbomify_action.cli.main import build_config, run_pipeline

#: The module, not the click command `sbomify_action.cli` re-exports as `main`.
cli_main = sys.modules["sbomify_action.cli.main"]

NAME = "sbomify Action"
VERSION = "1.2.3"
PURL = "pkg:docker/sbomify/sbomify-action@1.2.3?repository_url=ghcr.io"

ROOT = "SPDXRef-DocumentRoot-File-uv.lock"
ARROW = "SPDXRef-Package-python-arrow-9a674c0d42e22c36"
ATTRS = "SPDXRef-Package-python-attrs-e52aeb32f0af533a"

UV_LOCK = """\
version = 1
requires-python = ">=3.11"

[[package]]
name = "arrow"
version = "1.4.0"
source = { registry = "https://pypi.org/simple" }
"""


def package(spdx_id: str, name: str, version: str, purl: str | None = None) -> dict:
    entry: dict = {
        "SPDXID": spdx_id,
        "name": name,
        "versionInfo": version,
        "supplier": "NOASSERTION",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
    }
    if purl:
        entry["externalRefs"] = [
            {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": purl}
        ]
    return entry


def syft_uv_lock(spdx_version: str = "2.3") -> dict:
    """What syft 1.42 writes for uv.lock, cut down to two dependencies."""
    return {
        "spdxVersion": f"SPDX-{spdx_version}",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "uv.lock",
        "documentNamespace": "https://anchore.com/syft/file/uv.lock-bc7586df-c4cf-41d2-b755-a1b63691ff75",
        "creationInfo": {
            "creators": ["Organization: Anchore, Inc", "Tool: syft-1.42.4"],
            "created": "2026-10-26T10:36:23Z",
        },
        "packages": [
            package(ARROW, "arrow", "1.4.0", "pkg:pypi/arrow@1.4.0"),
            package(ATTRS, "attrs", "26.1.0", "pkg:pypi/attrs@26.1.0"),
            package(ROOT, "uv.lock", "sha256:d1a03d2bd4a3ade2714cc8d2394677c0a02c9e428f0409168ab20449d3d2c3be"),
        ],
        "relationships": [
            {"spdxElementId": ROOT, "relatedSpdxElement": ARROW, "relationshipType": "CONTAINS"},
            {"spdxElementId": ROOT, "relatedSpdxElement": ATTRS, "relationshipType": "CONTAINS"},
            {"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": ROOT, "relationshipType": "DESCRIBES"},
        ],
    }


def purls(entry: dict) -> list[str]:
    return [ref["referenceLocator"] for ref in entry.get("externalRefs", []) if ref["referenceType"] == "purl"]


def by_id(document: dict) -> dict[str, dict]:
    return {entry["SPDXID"]: entry for entry in document["packages"]}


def run_on_uv_lock(tmp_path: Path, monkeypatch, generated: dict, *, augment: bool) -> dict:
    """Run the pipeline the way .github/workflows/sboms.yml does, minus the upload.

    Generation is replaced by the document syft wrote for this repository's
    uv.lock, so the test needs no syft binary and pins the shape that broke.
    """
    monkeypatch.chdir(tmp_path)
    (tmp_path / "uv.lock").write_text(UV_LOCK)

    def syft(file_path, output_file, output_format, spec_version):
        Path(output_file).write_text(json.dumps(generated))
        return GenerationResult.success_result(
            output_file=output_file,
            sbom_format="spdx",
            spec_version=generated["spdxVersion"].removeprefix("SPDX-"),
            generator_name="syft-fs",
        )

    monkeypatch.setattr(cli_main, "process_lock_file", syft)
    config = build_config(
        lock_file="uv.lock",
        sbom_format="spdx",
        upload=False,
        augment=augment,
        enrich=False,
        component_name=NAME,
        component_version=VERSION,
        component_purl=PURL,
        output_file="out.spdx.json",
    )
    run_pipeline(config)
    return json.loads((tmp_path / "out.spdx.json").read_text())


@pytest.mark.parametrize("spdx_version", ["2.3", "2.2"])
@pytest.mark.parametrize("augment", [False], ids=["augment-off"])
def test_overrides_land_on_the_described_package(tmp_path, monkeypatch, spdx_version, augment):
    result = run_on_uv_lock(tmp_path, monkeypatch, syft_uv_lock(spdx_version), augment=augment)
    packages = by_id(result)

    arrow = packages[ARROW]
    assert (arrow["name"], arrow["versionInfo"], purls(arrow)) == ("arrow", "1.4.0", ["pkg:pypi/arrow@1.4.0"])

    root = packages[ROOT]
    assert root["versionInfo"] == VERSION
    assert purls(root) == [PURL]
    assert result["name"] == NAME


# ---------------------------------------------------------------------------
# The overrides alone, on documents that describe something other than one
# package, or nothing at all.


class Cfg:
    """The three fields the override functions read."""

    def __init__(self) -> None:
        self.component_name = NAME
        self.component_version = VERSION
        self.component_purl = PURL


def apply_overrides(tmp_path: Path, document: dict) -> dict:
    path = tmp_path / "sbom.spdx.json"
    path.write_text(json.dumps(document))
    config = Cfg()
    cli_main._apply_sbom_version_override(str(path), config)
    cli_main._apply_sbom_purl_override(str(path), config)
    return json.loads(path.read_text())


def test_documentdescribes_alone_names_the_root(tmp_path):
    document = syft_uv_lock()
    document["relationships"] = document["relationships"][:-1]
    document["documentDescribes"] = [ROOT]

    root = by_id(apply_overrides(tmp_path, document))[ROOT]
    assert (root["versionInfo"], purls(root)) == (VERSION, [PURL])


def test_with_several_described_packages_the_first_is_the_root(tmp_path):
    """Dependency expansion adds a DESCRIBES for every package it discovers,
    after the generator's own. The generator's root keeps the overrides."""
    document = syft_uv_lock()
    document["relationships"].append(
        {"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": ATTRS, "relationshipType": "DESCRIBES"}
    )

    packages = by_id(apply_overrides(tmp_path, document))
    assert (packages[ROOT]["versionInfo"], purls(packages[ROOT])) == (VERSION, [PURL])
    assert (packages[ATTRS]["versionInfo"], purls(packages[ATTRS])) == ("26.1.0", ["pkg:pypi/attrs@26.1.0"])


@pytest.mark.parametrize(
    "describes",
    [
        pytest.param(None, id="nothing-described"),
        pytest.param("SPDXRef-File-uv.lock-3717ae13dd3eb744", id="a-file-described"),
        pytest.param("SPDXRef-Package-not-in-this-document", id="a-dangling-reference"),
    ],
)
def test_without_a_described_package_no_package_is_touched(tmp_path, caplog, describes):
    document = syft_uv_lock()
    document["relationships"] = document["relationships"][:-1]
    if describes:
        document["relationships"].append(
            {"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": describes, "relationshipType": "DESCRIBES"}
        )

    assert apply_overrides(tmp_path, document)["packages"] == document["packages"]
    assert "describes no package" in caplog.text
