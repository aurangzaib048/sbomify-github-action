"""The release digest pin: scripts/pin_release_image.sh writes it in
release.yml, and scripts/verify_release_pin.sh gates every v* tag on it.

The registry is faked with a ``docker`` on PATH that prints $SERVED for
``docker buildx imagetools inspect``.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PINNED_FILES = ("action.yml", "pipe.yml", "bitbucket-pipelines.yml")
DIGEST = "sha256:" + "a" * 64
OTHER = "sha256:" + "b" * 64
VERSION = "26.10.3"


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    for name in PINNED_FILES:
        shutil.copy(ROOT / name, tmp_path / name)
    fake = tmp_path / "bin" / "docker"
    fake.parent.mkdir()
    fake.write_text('#!/bin/sh\nprintf %s "$SERVED"\n')
    fake.chmod(0o755)
    return tmp_path


def run(repo: Path, script: str, *args: str, served: str = DIGEST) -> subprocess.CompletedProcess[str]:
    env = {"PATH": f"{repo / 'bin'}:/usr/bin:/bin", "SERVED": served}
    return subprocess.run(
        [ROOT / "scripts" / script, *args], cwd=repo, env=env, capture_output=True, text=True, check=False
    )


def test_pin_replaces_only_latest(repo: Path) -> None:
    assert run(repo, "pin_release_image.sh", VERSION, DIGEST).returncode == 0
    for name, image in zip(
        PINNED_FILES,
        ("docker://ghcr.io/sbomify/sbomify-action", "sbomifyhub/sbomify-action", "docker://sbomifyhub/sbomify-action"),
    ):
        before = (ROOT / name).read_text()
        assert (repo / name).read_text() == before.replace(f"{image}:latest", f"{image}:{VERSION}@{DIGEST}"), name
        assert f"{image}:latest" in before, name


def test_verify_passes_on_correct_pin(repo: Path) -> None:
    run(repo, "pin_release_image.sh", VERSION, DIGEST)
    result = run(repo, "verify_release_pin.sh", VERSION)
    assert result.returncode == 0, result.stdout


@pytest.mark.parametrize(
    ("pin", "verify", "served"),
    [
        (None, VERSION, DIGEST),  # still :latest
        (VERSION, "26.10.4", DIGEST),  # tag is not the version pinned
        (VERSION, VERSION, OTHER),  # registry serves another digest
    ],
)
def test_verify_fails(repo: Path, pin: str | None, verify: str, served: str) -> None:
    if pin:
        run(repo, "pin_release_image.sh", pin, DIGEST)
    result = run(repo, "verify_release_pin.sh", verify, served=served)
    assert result.returncode == 1
    assert "::error::" in result.stdout


def test_verify_fails_when_pipe_pins_another_digest(repo: Path) -> None:
    run(repo, "pin_release_image.sh", VERSION, DIGEST)
    pipe = repo / "pipe.yml"
    pipe.write_text(pipe.read_text().replace(DIGEST, OTHER))
    assert run(repo, "verify_release_pin.sh", VERSION).returncode == 1
