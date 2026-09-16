"""Input file validation for packet captures (.pcap and .pcapng).

Validates file existence, format extension, size, permissions, and basic header sanity
without raising unhandled exceptions.
"""

from __future__ import annotations

from dataclasses import dataclass
import logging
import os
from pathlib import Path
from typing import Optional, Set

logger = logging.getLogger(__name__)

SUPPORTED_EXTENSIONS: Set[str] = {".pcap", ".pcapng"}

# Known magic numbers for PCAP and PCAPNG
PCAP_MAGIC_NUMBERS = {
    b"\xd4\xc3\xb2\xa1",  # Standard PCAP (microsecond, little-endian)
    b"\xa1\xb2\xc3\xd4",  # Standard PCAP (microsecond, big-endian)
    b"\x4d\x3c\xb2\xa1",  # Nanosecond PCAP (little-endian)
    b"\xa1\xb2\x3c\x4d",  # Nanosecond PCAP (big-endian)
}
PCAPNG_MAGIC_NUMBER = b"\x0a\x0d\x0d\x0a"  # Section Header Block


@dataclass
class ValidationResult:
    """Result of validating an input capture file."""

    is_valid: bool
    file_path: Path
    file_name: str
    file_type: str = "unknown"
    file_size: int = 0
    error_message: Optional[str] = None
    warning_message: Optional[str] = None


def validate_file_input(file_path: str | Path) -> ValidationResult:
    """Validate a PCAP/PCAPNG capture file.

    Checks:
    - Path validity and existence.
    - Regular file status (not a directory or socket).
    - Supported extension (.pcap, .pcapng case-insensitively).
    - Non-empty content (size > 0).
    - Read permissions.
    - Magic byte header check.

    Args:
        file_path: Path to the capture file.

    Returns:
        ValidationResult indicating success or specific validation error.
    """
    if not file_path:
        return ValidationResult(
            is_valid=False,
            file_path=Path(""),
            file_name="",
            error_message="Capture file path cannot be empty.",
        )

    try:
        path = Path(file_path).resolve()
    except Exception as e:
        logger.error("Failed to resolve file path %s: %s", file_path, e)
        return ValidationResult(
            is_valid=False,
            file_path=Path(str(file_path)),
            file_name=os.path.basename(str(file_path)),
            error_message=f"Invalid file path syntax: {e}",
        )

    file_name = path.name

    if not path.exists():
        msg = f"Capture file does not exist: {path}"
        logger.warning(msg)
        return ValidationResult(
            is_valid=False,
            file_path=path,
            file_name=file_name,
            error_message=msg,
        )

    if not path.is_file():
        msg = f"Path is not a regular file: {path}"
        logger.warning(msg)
        return ValidationResult(
            is_valid=False,
            file_path=path,
            file_name=file_name,
            error_message=msg,
        )

    ext = path.suffix.lower()
    if ext not in SUPPORTED_EXTENSIONS:
        msg = (
            f"Unsupported file extension '{ext}' for file '{file_name}'. "
            f"Supported extensions are: {', '.join(sorted(SUPPORTED_EXTENSIONS))}"
        )
        logger.warning(msg)
        return ValidationResult(
            is_valid=False,
            file_path=path,
            file_name=file_name,
            file_type=ext.lstrip(".") if ext else "unknown",
            error_message=msg,
        )

    file_type = "pcapng" if ext == ".pcapng" else "pcap"

    try:
        file_size = path.stat().st_size
    except OSError as e:
        msg = f"Unable to read file metadata for '{file_name}': {e}"
        logger.error(msg)
        return ValidationResult(
            is_valid=False,
            file_path=path,
            file_name=file_name,
            file_type=file_type,
            error_message=msg,
        )

    if file_size == 0:
        msg = f"Capture file '{file_name}' is empty (0 bytes)."
        logger.warning(msg)
        return ValidationResult(
            is_valid=False,
            file_path=path,
            file_name=file_name,
            file_type=file_type,
            file_size=0,
            error_message=msg,
        )

    if not os.access(path, os.R_OK):
        msg = f"Permission denied: capture file '{file_name}' is not readable."
        logger.error(msg)
        return ValidationResult(
            is_valid=False,
            file_path=path,
            file_name=file_name,
            file_type=file_type,
            file_size=file_size,
            error_message=msg,
        )

    # Magic byte sanity check
    try:
        with open(path, "rb") as f:
            header = f.read(4)
            if len(header) < 4:
                msg = f"File '{file_name}' is truncated (less than 4 bytes header)."
                return ValidationResult(
                    is_valid=False,
                    file_path=path,
                    file_name=file_name,
                    file_type=file_type,
                    file_size=file_size,
                    error_message=msg,
                )

            warning_msg = None
            if ext == ".pcapng":
                if header != PCAPNG_MAGIC_NUMBER:
                    warning_msg = (
                        f"File '{file_name}' has .pcapng extension but header "
                        f"{header.hex()} does not match standard PCAPNG magic number."
                    )
            elif ext == ".pcap":
                if header not in PCAP_MAGIC_NUMBERS:
                    warning_msg = (
                        f"File '{file_name}' has .pcap extension but header "
                        f"{header.hex()} does not match standard PCAP magic numbers."
                    )

            if warning_msg:
                logger.warning(warning_msg)

    except OSError as e:
        msg = f"Failed to read file header for '{file_name}': {e}"
        logger.error(msg)
        return ValidationResult(
            is_valid=False,
            file_path=path,
            file_name=file_name,
            file_type=file_type,
            file_size=file_size,
            error_message=msg,
        )

    return ValidationResult(
        is_valid=True,
        file_path=path,
        file_name=file_name,
        file_type=file_type,
        file_size=file_size,
        warning_message=warning_msg if 'warning_msg' in locals() else None,
    )
