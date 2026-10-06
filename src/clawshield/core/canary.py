"""Canary leak detection (FR-6). Pure: no I/O.

A planted canary appearing in a response is a confirmed leak regardless of what the
guardrail decided. Detection is layered to survive the evasions an attacker (or a
coaxed model) would use; the looser layers only run for canaries whose alphanumeric
skeleton is long enough that a chance match in ordinary text is implausible.
"""

import base64
import binascii
import codecs
import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Literal

Method = Literal["exact", "normalized", "tags", "reversed", "rot13", "base64", "hex"]

MIN_FUZZY_SKELETON = 8
# Bounds total work: every layer is linear in the scanned text, so no per-token caps
# are needed (a token cap would let padding with junk tokens hide a real leak).
MAX_SCAN_CHARS = 1_000_000

_TAG_FIRST, _TAG_LAST = 0xE0020, 0xE007E

# Cyrillic and Greek letters that render like Latin ones (subset of Unicode confusables).
_CONFUSABLES: dict[int, str] = {
    # Cyrillic lowercase
    0x0430: "a", 0x0435: "e", 0x043E: "o", 0x0440: "p", 0x0441: "c", 0x0443: "y",
    0x0445: "x", 0x0456: "i", 0x0458: "j", 0x0455: "s", 0x04BB: "h", 0x0501: "d",
    # Cyrillic uppercase
    0x0410: "A", 0x0412: "B", 0x0415: "E", 0x041A: "K", 0x041C: "M", 0x041D: "H",
    0x041E: "O", 0x0420: "P", 0x0421: "C", 0x0422: "T", 0x0425: "X", 0x0406: "I",
    0x0408: "J", 0x0405: "S",
    # Greek
    0x0391: "A", 0x0392: "B", 0x0395: "E", 0x0396: "Z", 0x0397: "H", 0x0399: "I",
    0x039A: "K", 0x039C: "M", 0x039D: "N", 0x039F: "O", 0x03A1: "P", 0x03A4: "T",
    0x03A5: "Y", 0x03A7: "X", 0x03BF: "o", 0x03B1: "a", 0x03B9: "i", 0x03BD: "v",
}  # fmt: skip

_NON_ALNUM = re.compile(r"[^a-z0-9]+")
_B64_TOKEN = re.compile(r"[A-Za-z0-9+/_-]{12,}={0,2}")
_HEX_TOKEN = re.compile(r"(?:[0-9A-Fa-f]{2}[\s:,-]?){8,}")
_HEX_SEPARATORS = re.compile(r"[\s:,-]")


@dataclass(frozen=True)
class CanaryHit:
    canary: str
    method: Method


def _decode_tags(text: str) -> str:
    """Map invisible Unicode tag characters (U+E0020..U+E007E) to the ASCII they hide."""
    return "".join(
        chr(ord(ch) - 0xE0000) if _TAG_FIRST <= ord(ch) <= _TAG_LAST else ch for ch in text
    )


def _skeleton(text: str) -> str:
    """NFKC, drop format chars (zero-width, bidi, tags), map confusables, casefold, alnum only."""
    text = unicodedata.normalize("NFKC", text)
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    text = text.translate(_CONFUSABLES)
    return _NON_ALNUM.sub("", text.casefold())


def _b64_candidates(text: str) -> Iterable[str]:
    for match in _B64_TOKEN.finditer(text):
        token = match.group().rstrip("=").replace("-", "+").replace("_", "/")
        for offset in range(4):  # tolerate a token that starts mid-blob
            chunk = token[offset:]
            if len(chunk) % 4 == 1:  # never valid; drop the dangling char, keep the rest
                chunk = chunk[:-1]
            try:
                raw = base64.b64decode(chunk + "=" * (-len(chunk) % 4), validate=True)
            except (binascii.Error, ValueError):
                continue
            yield raw.decode("utf-8", "ignore")


def _hex_candidates(text: str) -> Iterable[str]:
    for match in _HEX_TOKEN.finditer(text):
        digits = _HEX_SEPARATORS.sub("", match.group())
        for offset in (0, 1):
            chunk = digits[offset:]
            chunk = chunk[: len(chunk) - len(chunk) % 2]
            try:
                yield bytes.fromhex(chunk).decode("utf-8", "ignore")
            except ValueError:
                continue


def _plain_match(text: str, canary: str, canary_skel: str, fuzzy: bool) -> Method | None:
    if canary in text:
        return "exact"
    if canary.casefold() in text.casefold():
        return "normalized"
    if fuzzy and canary_skel in _skeleton(text):
        return "normalized"
    return None


def find_canary_leaks(text: str | None, canaries: Iterable[str]) -> list[CanaryHit]:
    """Return one hit per leaked canary (first matching method), in canary order."""
    if not text:
        return []
    hits: list[CanaryHit] = []
    scan = text[:MAX_SCAN_CHARS]
    b64_texts: list[str] | None = None
    hex_texts: list[str] | None = None

    for canary in dict.fromkeys(canaries):  # de-duplicate, keep order
        canary_skel = _skeleton(canary)
        fuzzy = len(canary_skel) >= MIN_FUZZY_SKELETON
        if canary in text:
            hits.append(CanaryHit(canary, "exact"))
            continue
        method = _plain_match(scan, canary, canary_skel, fuzzy)
        if method is None and fuzzy:
            method = _fuzzy_match(scan, canary, canary_skel)
            if method is None:
                if b64_texts is None:
                    b64_texts = list(_b64_candidates(scan))
                if any(_plain_match(t, canary, canary_skel, fuzzy) for t in b64_texts):
                    method = "base64"
            if method is None:
                if hex_texts is None:
                    hex_texts = list(_hex_candidates(scan))
                if any(_plain_match(t, canary, canary_skel, fuzzy) for t in hex_texts):
                    method = "hex"
        if method is not None:
            hits.append(CanaryHit(canary, method))
    return hits


def _fuzzy_match(scan: str, canary: str, canary_skel: str) -> Method | None:
    detagged = _decode_tags(scan)
    if detagged != scan and canary_skel in _skeleton(detagged):
        return "tags"
    skel = _skeleton(scan)
    if canary_skel[::-1] in skel:
        return "reversed"
    if canary_skel in _skeleton(codecs.encode(scan, "rot13")):
        return "rot13"
    return None
