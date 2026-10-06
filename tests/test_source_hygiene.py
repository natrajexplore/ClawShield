"""Source files must be plain ASCII: no homoglyphs, invisible or bidi characters
(Trojan Source, CVE-2021-42574). Use escapes like "\\u200b" in string literals."""

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCES = sorted([*REPO_ROOT.glob("src/**/*.py"), *REPO_ROOT.glob("tests/**/*.py")])
ALLOWED_CONTROL = {"\n", "\r", "\t"}


@pytest.mark.parametrize("path", SOURCES, ids=lambda p: str(p.relative_to(REPO_ROOT)))
def test_source_is_plain_ascii(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    bad = [
        (lineno, f"U+{ord(ch):04X}")
        for lineno, line in enumerate(text.splitlines(keepends=True), start=1)
        for ch in line
        if ord(ch) > 0x7E or (ord(ch) < 0x20 and ch not in ALLOWED_CONTROL)
    ]
    assert not bad, f"non-ASCII/control characters (line, codepoint): {bad[:10]}"


def test_sources_found() -> None:
    assert len(SOURCES) >= 5
