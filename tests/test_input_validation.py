"""Broken input fails clearly instead of crashing or passing silently.

Found by an audit of the action:

- A file whose top level is not a JSON object (``[]``, ``42``, ``null``)
  reached code that called ``.get()`` on it and crashed with
  ``AttributeError``, which telemetry then reported as a defect in the action.
- A CycloneDX ``SBOM_FILE`` that fails its schema (``"components": "oops"``)
  passed Step 1 and was written out unchanged with exit 0.
- ``AUGMENT=true`` with an ``sbomify.json`` that does not parse logged a
  warning, dropped the metadata it holds, and exited 0.
"""

import json

import pytest

from sbomify_action.console import reset_audit_trail
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


def _write(tmp_path, document):
    path = tmp_path / "sbom.json"
    path.write_text(json.dumps(document))
    return str(path)


def test_a_schema_invalid_cyclonedx_sbom_file_is_refused(tmp_path):
    from sbomify_action.cli.main import validate_sbom

    path = _write(tmp_path, {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": "oops"})

    with pytest.raises(SBOMValidationError, match="components"):
        validate_sbom(path)


def test_a_cyclonedx_sbom_file_without_a_spec_version_is_refused(tmp_path):
    from sbomify_action.cli.main import validate_sbom

    path = _write(tmp_path, {"bomFormat": "CycloneDX", "components": []})

    with pytest.raises(SBOMValidationError, match="specVersion"):
        validate_sbom(path)


def test_licence_shapes_the_pipeline_repairs_are_not_refused(tmp_path):
    """Trivy writes non-SPDX ids into license.id and cdxgen a bare string into
    license.text. Both fail the schema, and load_cyclonedx_bom repairs both,
    so refusing them here would break inputs the pipeline already handles.

    The trial repair must not reach the audit trail: the real one, later,
    records it, and recording it twice would misstate what was changed.
    """
    from sbomify_action.cli.main import validate_sbom

    path = _write(
        tmp_path,
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [
                {"type": "library", "name": "a", "licenses": [{"license": {"id": "GPLv2+"}}]},
                {"type": "library", "name": "b", "licenses": [{"license": {"name": "x", "text": "Copyright"}}]},
            ],
        },
    )
    trail = reset_audit_trail()

    assert validate_sbom(path) == "cyclonedx"
    assert trail.entries == []


def _sbom_file_config(tmp_path, monkeypatch, document, **options):
    from sbomify_action.cli.main import build_config

    monkeypatch.chdir(tmp_path)
    return build_config(sbom_file=_write(tmp_path, document), upload=False, output_file="out.json", **options)


def test_the_pipeline_stops_at_step_1_on_a_schema_invalid_sbom_file(tmp_path, monkeypatch):
    from sbomify_action.cli.main import run_pipeline

    config = _sbom_file_config(
        tmp_path, monkeypatch, {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": "oops"}
    )

    with pytest.raises(SystemExit) as exc:
        run_pipeline(config)
    assert exc.value.code == 1
    assert not (tmp_path / "out.json").exists()


def test_an_sbom_file_with_no_components_still_passes(tmp_path, monkeypatch):
    """Only a lock file that yields nothing is suspect. A supplied SBOM that
    lists no components may be exactly right."""
    from sbomify_action.cli.main import run_pipeline

    config = _sbom_file_config(
        tmp_path, monkeypatch, {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}
    )

    run_pipeline(config)

    assert json.loads((tmp_path / "out.json").read_text())["components"] == []


def test_augment_stops_on_an_sbomify_json_it_cannot_read(tmp_path, monkeypatch):
    """AUGMENT=true with a malformed sbomify.json used to log a warning, drop
    the supplier and author metadata, and exit 0."""
    from sbomify_action.cli.main import run_pipeline

    config = _sbom_file_config(
        tmp_path, monkeypatch, {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}, augment=True
    )
    (tmp_path / "sbomify.json").write_text('{"supplier": {"name": "Acme"},}')

    with pytest.raises(SystemExit) as exc:
        run_pipeline(config)
    assert exc.value.code == 1
