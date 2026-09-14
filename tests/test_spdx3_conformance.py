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


class TestTheSpecVersionSurvives:
    """SPDX 3.0 shipped 2024-04 and 3.0.1 in 2024-12. Both are in the wild:
    syft, Microsoft sbom-tool, JFrog Xray and Zephyr all emit 3.0.

    The writer hardcoded a 3.0.1 @context and none of its eight call sites
    overrode it, so a 3.0 input came back labelled 3.0.1 in the @context while
    its creationInfo still read 3.0.0. CycloneDX already reads the output spec
    version off the input document.
    """

    def _as_300(self) -> dict:
        source = json.loads(FIXTURE.read_text())
        source["@context"] = "https://spdx.org/rdf/3.0.0/spdx-context.jsonld"
        for element in source["@graph"]:
            if element.get("type") == "CreationInfo":
                element["specVersion"] = "3.0.0"
        return source

    def _write(self, source: dict, tmp_path: Path) -> dict:
        out = tmp_path / "out.json"
        write_spdx3_file(parse_spdx3_data(source), str(out))
        return json.loads(out.read_text())

    def test_a_300_input_stays_300(self, tmp_path):
        result = self._write(self._as_300(), tmp_path)

        assert result["@context"] == "https://spdx.org/rdf/3.0.0/spdx-context.jsonld"

    def test_the_context_and_the_spec_version_agree(self, tmp_path):
        """Relabelling one and not the other is worse than either alone."""
        result = self._write(self._as_300(), tmp_path)

        assert _creation_infos(result)[0]["specVersion"] == "3.0.0"

    def test_a_301_input_stays_301(self, tmp_path):
        result = self._write(json.loads(FIXTURE.read_text()), tmp_path)

        assert result["@context"] == "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"

    def test_a_document_built_from_nothing_is_301(self, tmp_path):
        """Nothing to preserve, so write the current release."""
        from sbomify_action.spdx3 import Spdx3Payload

        out = tmp_path / "out.json"
        write_spdx3_file(Spdx3Payload(), str(out))

        assert json.loads(out.read_text())["@context"] == "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"

    def test_an_explicit_argument_still_wins(self, tmp_path):
        out = tmp_path / "out.json"
        pinned = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"

        write_spdx3_file(parse_spdx3_data(self._as_300()), str(out), context_url=pinned)

        assert json.loads(out.read_text())["@context"] == pinned


class TestPurposesTheLibraryHasNotHeardOf:
    """spdx-tools 0.8.5 carries the pre-3.0.1 SoftwarePurpose enum.

    It has neither `specification` nor `filesystemImage`, both of which 3.0.1
    defines and Yocto emits. Measured on the published 6.0.3 core-image-minimal
    SBOM, which validates clean: a round-trip dropped primaryPurpose from 38
    packages, `filesystemImage` among them. That one is the image itself.

    A value the producer wrote and the schema accepts does not get dropped
    because a library is a version behind.
    """

    def _package(self, source: dict) -> dict:
        return [e for e in source["@graph"] if e.get("type") == "software_Package"][0]

    def _round_trip(self, purpose: str, tmp_path: Path, key: str = "software_primaryPurpose") -> dict:
        source = json.loads(FIXTURE.read_text())
        self._package(source)[key] = purpose
        out = tmp_path / "out.json"
        write_spdx3_file(parse_spdx3_data(source), str(out))
        return json.loads(out.read_text())

    @pytest.mark.parametrize("purpose", ["specification", "filesystemImage"])
    def test_a_3_0_1_purpose_survives(self, purpose, tmp_path, validator):
        result = self._round_trip(purpose, tmp_path)

        assert _elements(result, "software_Package")[0]["software_primaryPurpose"] == purpose
        assert _errors(validator, result) == []

    @pytest.mark.parametrize("purpose", ["library", "source", "install", "archive", "patch"])
    def test_a_purpose_the_library_knows_still_survives(self, purpose, tmp_path):
        result = self._round_trip(purpose, tmp_path)

        assert _elements(result, "software_Package")[0]["software_primaryPurpose"] == purpose

    def test_additional_purposes_survive_too(self, tmp_path, validator):
        """Same enum, same gap, and it takes a list."""
        result = self._round_trip("specification", tmp_path, key="software_additionalPurpose")
        package = _elements(result, "software_Package")[0]

        assert package["software_additionalPurpose"] == ["specification"]
        assert _errors(validator, result) == []

    def test_a_package_without_a_purpose_is_not_given_one(self, tmp_path):
        source = json.loads(FIXTURE.read_text())
        out = tmp_path / "out.json"

        write_spdx3_file(parse_spdx3_data(source), str(out))
        package = _elements(json.loads(out.read_text()), "software_Package")[0]

        assert "software_primaryPurpose" not in package
