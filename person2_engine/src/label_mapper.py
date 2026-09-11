"""Explicit label mapping layer for canonical encrypted traffic categories.

Provides deterministic mapping from dataset-specific raw application or protocol strings
to the project's canonical 5-class target taxonomy without silent or arbitrary merging.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Sequence

# Canonical project application categories
CANONICAL_CATEGORIES: List[str] = [
    "web",
    "streaming",
    "video",
    "voip",
    "file_transfer",
    "interactive",
]

# Documented baseline mapping for known encrypted traffic datasets (ISCX-VPN, CIC, etc.)
DEFAULT_LABEL_MAPPING: Dict[str, str] = {
    # Web / Browsing
    "web": "web",
    "browsing": "web",
    "http": "web",
    "https": "web",
    "vpn_browsing": "web",
    "tor_browsing": "web",

    # Video Streaming (streaming / video)
    "streaming": "streaming",
    "video": "video",
    "youtube": "video",
    "vimeo": "video",
    "netflix": "video",
    "vpn_youtube": "video",
    "vpn_vimeo": "video",
    "vpn_netflix": "video",
    "vpn_streaming": "streaming",

    # Voice / Real-time Audio
    "voip": "voip",
    "audio": "voip",
    "voice": "voip",
    "skype": "voip",
    "hangouts": "voip",
    "facebook_audio": "voip",
    "vpn_skype": "voip",
    "vpn_hangouts": "voip",
    "vpn_voip": "voip",

    # File Transfer / Bulk
    "file_transfer": "file_transfer",
    "ftp": "file_transfer",
    "sftp": "file_transfer",
    "ftps": "file_transfer",
    "scp": "file_transfer",
    "torrent": "file_transfer",
    "bittorrent": "file_transfer",
    "vpn_ftps": "file_transfer",
    "vpn_sftp": "file_transfer",
    "vpn_bittorrent": "file_transfer",

    # Interactive / Messaging / Shell
    "interactive": "interactive",
    "chat": "interactive",
    "ssh": "interactive",
    "telnet": "interactive",
    "facebook_chat": "interactive",
    "hangouts_chat": "interactive",
    "skype_chat": "interactive",
    "discord": "voip",
    "zoom": "voip",
    "teams": "voip",
}


class LabelMapper:
    """Transforms raw dataset labels into verified canonical categories."""

    def __init__(
        self,
        custom_mapping: Optional[Dict[str, str]] = None,
        allow_identity: bool = True,
        fallback_label: Optional[str] = None,
    ) -> None:
        """Initialize label mapper.

        Args:
            custom_mapping: Optional user-supplied mapping dict overriding defaults.
            allow_identity: If True, labels already in CANONICAL_CATEGORIES are preserved.
            fallback_label: Optional default category for unmapped strings (if None, raises ValueError).
        """
        self.mapping: Dict[str, str] = dict(DEFAULT_LABEL_MAPPING)
        if custom_mapping:
            for k, v in custom_mapping.items():
                v_clean = v.lower().strip()
                if v_clean not in CANONICAL_CATEGORIES:
                    raise ValueError(
                        f"Target category '{v}' is not in canonical categories: {CANONICAL_CATEGORIES}"
                    )
                self.mapping[k.lower().strip()] = v_clean

        if fallback_label and fallback_label not in CANONICAL_CATEGORIES:
            raise ValueError(
                f"Fallback category '{fallback_label}' is not in canonical categories: {CANONICAL_CATEGORIES}"
            )

        self.allow_identity = allow_identity
        self.fallback_label = fallback_label

    def map_label(self, raw_label: str) -> str:
        """Map a single raw label string to its canonical class.

        Args:
            raw_label: Input string from dataset.

        Returns:
            Canonical category string.

        Raises:
            ValueError: If label cannot be mapped and no fallback is set.
        """
        cleaned = str(raw_label).lower().strip()

        if cleaned in self.mapping:
            return self.mapping[cleaned]

        if self.allow_identity and cleaned in CANONICAL_CATEGORIES:
            return cleaned

        if self.fallback_label:
            return self.fallback_label

        raise ValueError(
            f"Unmapped dataset label: '{raw_label}'. "
            f"Explicit mapping required to map into canonical categories: {CANONICAL_CATEGORIES}."
        )

    def map_sequence(self, labels: Sequence[str]) -> List[str]:
        """Map a sequence of labels.

        Args:
            labels: List or sequence of raw label strings.

        Returns:
            List of canonical labels.
        """
        return [self.map_label(lbl) for lbl in labels]
