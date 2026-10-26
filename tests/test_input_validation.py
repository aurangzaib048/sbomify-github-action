"""Broken input fails clearly instead of crashing or passing silently.

Found by an audit of the action:

- A file whose top level is not a JSON object (``[]``, ``42``, ``null``)
  reached code that called ``.get()`` on it and crashed with
  ``AttributeError``, which telemetry then reported as a defect in the action.
"""

import pytest

from sbomify_action.exceptions import FileProcessingError, SBOMValidationError

NOT_OBJECTS = ["[]", "42", "null", '"sbom"']


def test_load_sbom_json_returns_an_object(tmp_path):
    from sbomify_action.serialization import load_sbom_json

    path = tmp_path / "sbom.json"
    path.write_text('{"bomFormat": "CycloneDX"}')
    assert load_sbom_json(str(path)) == {"bomFormat": "CycloneDX"}


@pytest.mark.parametrize("body", NOT_OBJECTS)
def test_load_sbom_json_refuses_anything_but_an_object(tmp_path, body):
    from sbomify_action.serialization import load_sbom_json

    path = tmp_path / "sbom.json"
    path.write_text(body)
    with pytest.raises(SBOMValidationError, match="JSON object"):
        load_sbom_json(str(path))


def _validate(path, tmp_path):
    from sbomify_action.cli.main import validate_sbom

    return validate_sbom(path)


def _detect_silently(path, tmp_path):
    from sbomify_action.cli.main import _detect_sbom_format_silent

    return _detect_sbom_format_silent(path)


def _load(path, tmp_path):
    from sbomify_action.cli.main import load_sbom_from_file

    return load_sbom_from_file(path)


def _augment(path, tmp_path):
    from sbomify_action.augmentation import augment_sbom_from_file

    return augment_sbom_from_file(path, str(tmp_path / "out.json"))


def _enrich(path, tmp_path):
    from sbomify_action.enrichment import enrich_sbom

    return enrich_sbom(path, str(tmp_path / "out.json"))


def _inject(path, tmp_path):
    from sbomify_action.additional_packages import inject_additional_packages

    return inject_additional_packages(path)


def _hashes(path, tmp_path):
    from sbomify_action._hash_enrichment import enrich_sbom_with_hashes

    return enrich_sbom_with_hashes(path, str(tmp_path / "uv.lock"))


def _expand(path, tmp_path):
    from sbomify_action._dependency_expansion.enricher import DependencyEnricher

    return DependencyEnricher().expand_sbom(path, str(tmp_path / "requirements.txt"))


@pytest.mark.parametrize(
    "site",
    [_validate, _detect_silently, _load, _augment, _enrich, _inject, _hashes, _expand],
    ids=lambda f: f.__name__.lstrip("_"),
)
def test_every_reader_refuses_a_non_object_cleanly(tmp_path, monkeypatch, site):
    """Each of these called ``.get()`` on whatever ``json.load`` returned."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ADDITIONAL_PACKAGES", "pkg:pypi/extra@1.0.0")
    path = tmp_path / "sbom.json"
    path.write_text("[]")

    with pytest.raises(SBOMValidationError, match="JSON object"):
        site(str(path), tmp_path)


def test_yocto_discovery_skips_a_non_object_instead_of_crashing(tmp_path):
    from sbomify_action._yocto.parser import discover_packages

    (tmp_path / "broken.spdx.json").write_text("[]")

    with pytest.raises(FileProcessingError, match="No package SBOMs"):
        discover_packages(str(tmp_path))
