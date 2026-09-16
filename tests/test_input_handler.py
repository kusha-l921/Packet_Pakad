"""Unit tests for input file validation in person2_engine.src.input_handler."""

from pathlib import Path
from person2_engine.src.input_handler import validate_file_input


def test_missing_file():
    """Verify that validating a non-existent file returns invalid with a clear error."""
    result = validate_file_input("/path/does/not/exist/test.pcap")
    assert not result.is_valid
    assert "does not exist" in result.error_message


def test_empty_path():
    """Verify that an empty path string returns invalid without crashing."""
    result = validate_file_input("")
    assert not result.is_valid
    assert "cannot be empty" in result.error_message


def test_directory_path(tmp_path: Path):
    """Verify that passing a directory instead of a regular file returns invalid."""
    result = validate_file_input(tmp_path)
    assert not result.is_valid
    assert "not a regular file" in result.error_message


def test_unsupported_extension(unsupported_ext_file: Path):
    """Verify that unsupported extensions are rejected."""
    result = validate_file_input(unsupported_ext_file)
    assert not result.is_valid
    assert "Unsupported file extension" in result.error_message


def test_empty_pcap(empty_pcap: Path):
    """Verify that 0-byte PCAP files are rejected gracefully."""
    result = validate_file_input(empty_pcap)
    assert not result.is_valid
    assert "is empty (0 bytes)" in result.error_message


def test_empty_pcapng(empty_pcapng: Path):
    """Verify that 0-byte PCAPNG files are rejected gracefully."""
    result = validate_file_input(empty_pcapng)
    assert not result.is_valid
    assert "is empty (0 bytes)" in result.error_message


def test_valid_pcap(valid_basic_pcap: Path):
    """Verify that a valid PCAP file passes validation."""
    result = validate_file_input(valid_basic_pcap)
    assert result.is_valid
    assert result.file_type == "pcap"
    assert result.file_size > 0
    assert result.error_message is None


def test_valid_pcapng(valid_pcapng: Path):
    """Verify that a valid PCAPNG file passes validation."""
    result = validate_file_input(valid_pcapng)
    assert result.is_valid
    assert result.file_type == "pcapng"
    assert result.file_size > 0
    assert result.error_message is None


def test_corrupted_header_pcap(corrupted_pcap: Path):
    """Verify that a file with non-PCAP magic bytes issues a warning or handles gracefully."""
    result = validate_file_input(corrupted_pcap)
    # The file has valid extension and size, but bad magic number generates a warning
    assert result.warning_message is not None
    assert "magic" in result.warning_message.lower()
