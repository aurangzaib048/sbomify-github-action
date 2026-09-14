"""What the action writes must pass the schema the action ships.

Every SPDX 3 file the writer produced failed `spdx-3.0.1.schema.json`, the
copy bundled in this repo, because spdx-tools 0.8.5 models a pre-3.0.1 draft:
its CreationInfo still carries `profile` and `data_license`, both of which
3.0.1 moved or removed. `CreationInfo_props` allows exactly
comment/created/createdBy/createdUsing/specVersion under
`unevaluatedProperties: false`, so one extra key invalidates every element in
the document.

That is what makes AUGMENT=true or ENRICH=true on any SPDX 3 input an
unconditional exit 1: both re-validate their own output.
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from sbomify_action.spdx3 import parse_spdx3_data, parse_spdx3_file, write_spdx3_file

FIXTURE = Path(__file__).parent / "test-data" / "spdx3_conformant.json"
SCHEMA = Path(__file__).parent.parent / "sbomify_action" / "schemas" / "spdx" / "spdx-3.0.1.schema.json"


@pytest.fixture(scope="module")
def validator() -> jsonschema.Draft202012Validator:
    return jsonschema.Draft202012Validator(json.loads(SCHEMA.read_text()))


def _errors(validator, document: dict) -> list[str]:
    return [
        "/" + "/".join(str(p) for p in e.absolute_path) + ": " + e.message[:200]
        for e in validator.iter_errors(document)
    ]


@pytest.fixture
def round_tripped(tmp_path: Path) -> dict:
    out = tmp_path / "out.json"
    write_spdx3_file(parse_spdx3_file(str(FIXTURE)), str(out))
    return json.loads(out.read_text())


def _elements(document: dict, type_name: str) -> list[dict]:
    return [e for e in document.get("@graph", []) if e.get("type") == type_name]


def _creation_infos(node) -> list[dict]:
    """Every CreationInfo in the document, inline or standalone."""
    found = []
    if isinstance(node, dict):
        if node.get("type") == "CreationInfo" or "specVersion" in node:
            found.append(node)
        for value in node.values():
            found.extend(_creation_infos(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(_creation_infos(item))
    return found


class TestTheControlIsActuallyValid:
    """Without this the round-trip assertion below proves nothing.

    The repo's other fixture, spdx3_minimal.json, is not a control: it uses
    `@id` rather than `spdxId`, carries no `@context`, and fails the schema
    eight times on its own.
    """

    def test_the_fixture_validates_before_anything_touches_it(self, validator):
        assert _errors(validator, json.loads(FIXTURE.read_text())) == []


class TestTheRoundTripStaysValid:
    def test_a_valid_document_comes_back_valid(self, validator, round_tripped):
        assert _errors(validator, round_tripped) == []

    def test_no_creation_info_carries_datalicense(self, round_tripped):
        """3.0.1 moved it to SpdxDocument."""
        assert [ci for ci in _creation_infos(round_tripped) if "dataLicense" in ci] == []

    def test_no_creation_info_carries_profile(self, round_tripped):
        """3.0.1 replaced it with Element.profileConformance."""
        assert [ci for ci in _creation_infos(round_tripped) if "profile" in ci] == []

    def test_a_document_that_declared_no_datalicense_is_not_given_one(self, round_tripped):
        """The draft model defaults data_license to the bare id "CC0-1.0",
        which is both a claim its author never made and invalid where the
        schema wants a licence IRI."""
        assert "dataLicense" not in _elements(round_tripped, "SpdxDocument")[0]

    def test_external_refs_keep_the_3_0_1_spelling(self, round_tripped):
        """spdx-tools writes externalReference / externalReferenceType /
        ExternalReference; 3.0.1 renamed all three and rejects the old names."""
        package = _elements(round_tripped, "software_Package")[0]

        assert "externalReference" not in package
        assert package["externalRef"][0]["externalRefType"] == "vcs"
        assert package["externalRef"][0]["type"] == "ExternalRef"

    def test_the_document_keeps_its_profile_conformance(self, round_tripped):
        """Listing a profile claims every contained element meets it, so
        dropping it silently weakens the document."""
        assert _elements(round_tripped, "SpdxDocument")[0]["profileConformance"] == ["core", "software"]

    def test_the_packages_survive(self, round_tripped):
        names = {p.get("name") for p in _elements(round_tripped, "software_Package")}

        assert names == {"my-app"}


class TestDocumentsThatDeclareNothing:
    def test_a_document_without_profile_conformance_does_not_gain_one(self, tmp_path, validator):
        source = json.loads(FIXTURE.read_text())
        for element in source["@graph"]:
            element.pop("profileConformance", None)
        out = tmp_path / "out.json"

        write_spdx3_file(parse_spdx3_data(source), str(out))
        result = json.loads(out.read_text())

        assert "profileConformance" not in _elements(result, "SpdxDocument")[0]
        assert _errors(validator, result) == []

    def test_a_legacy_creation_info_profile_is_not_re_emitted(self, tmp_path, validator):
        """The repo's own older fixtures put `profile` on the CreationInfo.
        Reading it is fine; writing it back out is not."""
        source = json.loads(FIXTURE.read_text())
        for element in source["@graph"]:
            if element.get("type") == "CreationInfo":
                element["profile"] = ["core", "software"]
                element["dataLicense"] = "CC0-1.0"
        out = tmp_path / "out.json"

        write_spdx3_file(parse_spdx3_data(source), str(out))
        result = json.loads(out.read_text())

        assert [ci for ci in _creation_infos(result) if "profile" in ci or "dataLicense" in ci] == []
        assert _errors(validator, result) == []


class TestADeclaredDataLicense:
    """3.0.1 puts it on the SpdxDocument, as a licence IRI."""

    LICENSE = "https://spdx.org/licenses/CC0-1.0"

    def _write(self, source: dict, tmp_path: Path) -> dict:
        out = tmp_path / "out.json"
        write_spdx3_file(parse_spdx3_data(source), str(out))
        return json.loads(out.read_text())

    def test_it_survives_on_the_document(self, tmp_path, validator):
        source = json.loads(FIXTURE.read_text())
        for element in source["@graph"]:
            if element.get("type") == "SpdxDocument":
                element["dataLicense"] = self.LICENSE

        result = self._write(source, tmp_path)

        assert _elements(result, "SpdxDocument")[0]["dataLicense"] == self.LICENSE
        assert _errors(validator, result) == []

    def test_the_draft_location_is_read_and_rewritten_to_the_document(self, tmp_path, validator):
        """Older documents put it on the CreationInfo. Read it there, write it
        where 3.0.1 expects it."""
        source = json.loads(FIXTURE.read_text())
        for element in source["@graph"]:
            if element.get("type") == "SpdxDocument":
                element["creationInfo"] = {
                    "type": "CreationInfo",
                    "specVersion": "3.0.1",
                    "created": "2026-08-01T00:00:00Z",
                    "createdBy": ["urn:acme:agent"],
                    "dataLicense": self.LICENSE,
                }

        result = self._write(source, tmp_path)
        document = _elements(result, "SpdxDocument")[0]

        assert document["dataLicense"] == self.LICENSE
        assert "dataLicense" not in document["creationInfo"]
        assert _errors(validator, result) == []
