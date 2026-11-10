"""Regression tests for archive extraction and ingestion security."""

import io
import tempfile
import zipfile
from pathlib import Path

import pytest

from vibesec.extractor import (
    DANGEROUS_EXTENSIONS,
    MAX_ARCHIVE_BYTES,
    MAX_ARCHIVE_MEMBERS,
    ExtractionError,
    clone_github,
    extract_zip,
)


def _make_zip(files: dict[str, str | bytes]) -> Path:
    td = Path(tempfile.mkdtemp())
    zip_path = td / "test.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            if isinstance(content, str):
                zf.writestr(name, content.encode("utf-8"))
            else:
                zf.writestr(name, content)
    return zip_path


def test_extract_valid_zip():
    td_dest = Path(tempfile.mkdtemp())
    zip_p = _make_zip({"app.py": "print('hello')", "requirements.txt": "fastapi==0.100.0"})
    extracted = extract_zip(zip_p, td_dest)
    assert extracted.is_dir()
    assert (extracted / "app.py").is_file()
    assert (extracted / "requirements.txt").is_file()


def test_extract_zip_single_top_level_descends():
    td_dest = Path(tempfile.mkdtemp())
    zip_p = _make_zip({"project-main/app.py": "print('ok')", "project-main/README.md": "# Readme"})
    extracted = extract_zip(zip_p, td_dest)
    assert extracted.name == "project-main"
    assert (extracted / "app.py").is_file()


def test_extract_zip_with_ds_store_metadata_still_descends():
    td_dest = Path(tempfile.mkdtemp())
    zip_p = _make_zip({
        "project-main/app.py": "print('ok')",
        "project-main/README.md": "# Readme",
        ".DS_Store": "junk",
        "__MACOSX/._app.py": "mac meta",
    })
    extracted = extract_zip(zip_p, td_dest)
    assert extracted.name == "project-main"
    assert (extracted / "app.py").is_file()


def test_reject_path_traversal():
    td_dest = Path(tempfile.mkdtemp())
    zip_p = _make_zip({"../../evil.txt": "malicious content"})
    with pytest.raises(ExtractionError, match="Unsafe archive entry rejected"):
        extract_zip(zip_p, td_dest)


def test_reject_absolute_path():
    td_dest = Path(tempfile.mkdtemp())
    zip_p = _make_zip({"/etc/passwd": "root:x:0:0"})
    with pytest.raises(ExtractionError, match="Unsafe archive entry rejected"):
        extract_zip(zip_p, td_dest)


def test_reject_windows_drive():
    td_dest = Path(tempfile.mkdtemp())
    zip_p = _make_zip({"C:/Windows/System32/evil.dll": "fake"})
    with pytest.raises(ExtractionError, match="Unsafe archive entry rejected"):
        extract_zip(zip_p, td_dest)


def test_reject_dangerous_binary_extension():
    td_dest = Path(tempfile.mkdtemp())
    zip_p = _make_zip({"malware.exe": b"MZ\x90\x00\x03\x00\x00\x00"})
    with pytest.raises(ExtractionError, match="binary executable not allowed"):
        extract_zip(zip_p, td_dest)


def test_reject_corrupt_zip():
    td_dest = Path(tempfile.mkdtemp())
    corrupt_zip = Path(tempfile.mkdtemp()) / "corrupt.zip"
    corrupt_zip.write_bytes(b"not a valid zip file header")
    with pytest.raises(ExtractionError, match="Corrupted or invalid ZIP archive"):
        extract_zip(corrupt_zip, td_dest)


def test_reject_oversized_members_count():
    td_dest = Path(tempfile.mkdtemp())
    many_files = {f"file_{i}.txt": "a" for i in range(MAX_ARCHIVE_MEMBERS + 5)}
    zip_p = _make_zip(many_files)
    with pytest.raises(ExtractionError, match="entries exceeds"):
        extract_zip(zip_p, td_dest)


def test_github_invalid_url():
    td_dest = Path(tempfile.mkdtemp())
    with pytest.raises(ExtractionError, match="Only public https://github.com"):
        clone_github("https://gitlab.com/owner/repo", td_dest)

    with pytest.raises(ExtractionError, match="Only public https://github.com"):
        clone_github("not-a-url", td_dest)

