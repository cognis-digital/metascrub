"""METASCRUB - strip identifying metadata from documents and images before release.

Defensive, analysis-and-sanitization tool. Operates only on local files the
operator owns or is authorized to clean. No network access. Standard library only.

Spiritual cousin of mat2: "clean before ship".
"""

from .core import (
    Finding,
    ScrubResult,
    scan_file,
    clean_file,
    SUPPORTED_FORMATS,
    detect_format,
)

TOOL_NAME = "metascrub"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "Finding",
    "ScrubResult",
    "scan_file",
    "clean_file",
    "SUPPORTED_FORMATS",
    "detect_format",
]
