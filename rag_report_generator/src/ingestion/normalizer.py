"""Document normalization utilities."""

import re


class DocumentNormalizer:
    """Normalizes raw text content across various document formats."""

    @staticmethod
    def normalize(text: str) -> str:
        """Standardize newlines, clean excessive whitespace, preserve markdown structure."""
        if not text:
            return ""

        # Remove byte-order marks
        text = text.lstrip("\ufeff")

        # Standardize carriage returns to standard Unix newlines
        text = text.replace("\r\n", "\n").replace("\r", "\n")

        # Strip trailing whitespace on each line
        lines = [line.rstrip() for line in text.split("\n")]
        text = "\n".join(lines)

        # Collapse 3 or more consecutive blank lines down to 2
        text = re.sub(r"\n{3,}", "\n\n", text)

        return text.strip()
