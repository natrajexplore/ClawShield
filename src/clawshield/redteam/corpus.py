"""Load and validate the labeled JSONL attack corpus (FR-3).

The whole file is checked and every problem is reported with its line number.
Case text is data only: it is never executed, rendered as markup or normalized.
"""

import hashlib
import json
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from pydantic import ValidationError

from clawshield.core.models import Case, Category

MAX_CORPUS_BYTES = 50 * 1024 * 1024
MAX_CASES = 100_000
MAX_REPORTED_ISSUES = 50


class CorpusError(Exception):
    """The corpus file is unreadable or contains invalid cases."""

    def __init__(self, path: Path, issues: list[str]) -> None:
        self.path = path
        self.issues = issues
        shown = issues[:MAX_REPORTED_ISSUES]
        more = len(issues) - len(shown)
        lines = [f"invalid corpus {path} ({len(issues)} issue(s)):", *(f"  {i}" for i in shown)]
        if more:
            lines.append(f"  ... and {more} more")
        super().__init__("\n".join(lines))


@dataclass(frozen=True)
class Corpus:
    path: Path
    sha256: str
    cases: tuple[Case, ...]

    def category_counts(self) -> dict[Category, int]:
        counts = dict.fromkeys(Category, 0)
        for case in self.cases:
            counts[case.category] += 1
        return counts


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    obj: dict[str, object] = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"duplicate key {key!r}")
        obj[key] = value
    return obj


def _reject_constant(name: str) -> object:
    raise ValueError(f"non-standard JSON constant {name}")


def _parse_line(raw: str) -> object:
    return json.loads(
        raw, object_pairs_hook=_reject_duplicate_keys, parse_constant=_reject_constant
    )


def _format_validation(lineno: int, exc: ValidationError) -> list[str]:
    issues = []
    for err in exc.errors(include_input=False, include_url=False):
        loc = ".".join(str(p) for p in err["loc"])
        where = f" {loc}:" if loc else ""
        issues.append(f"line {lineno}:{where} {err['msg']}")
    return issues


def load_corpus(path: Path, *, known_canaries: Iterable[str] = ()) -> Corpus:
    """Load a JSONL corpus. Raises CorpusError listing every invalid line.

    `known_canaries` are the canaries from config; a case naming any other canary is
    rejected, because leak detection would silently never match it.
    """
    try:
        if path.stat().st_size > MAX_CORPUS_BYTES:
            raise CorpusError(path, [f"file exceeds {MAX_CORPUS_BYTES} bytes"])
        data = path.read_bytes()
    except OSError as exc:
        raise CorpusError(path, [f"cannot read file: {exc.strerror}"]) from None
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise CorpusError(path, [f"not valid UTF-8 at byte {exc.start}"]) from None

    canaries = frozenset(known_canaries)
    issues: list[str] = []
    cases: list[Case] = []
    first_seen: dict[str, int] = {}

    # Split on "\n" only: str.splitlines() would also split on U+2028 etc., which are
    # legal unescaped inside JSON strings.
    for lineno, raw in enumerate(text.split("\n"), start=1):
        line = raw.rstrip("\r")
        if not line.strip():
            continue
        try:
            obj = _parse_line(line)
        except ValueError as exc:  # json.JSONDecodeError is a ValueError
            reason = exc.msg if isinstance(exc, json.JSONDecodeError) else str(exc)
            issues.append(f"line {lineno}: invalid JSON: {reason}")
            continue
        if not isinstance(obj, dict):
            issues.append(f"line {lineno}: expected a JSON object")
            continue
        try:
            case = Case.model_validate(obj)
        except ValidationError as exc:
            issues.extend(_format_validation(lineno, exc))
            continue
        if case.id in first_seen:
            issues.append(
                f"line {lineno}: duplicate id {case.id!r} (first on line {first_seen[case.id]})"
            )
            continue
        if case.canary is not None and case.canary not in canaries:
            issues.append(f"line {lineno}: canary {case.canary!r} is not in config canaries")
            continue
        first_seen[case.id] = lineno
        cases.append(case)
        if len(cases) > MAX_CASES:
            issues.append(f"more than {MAX_CASES} cases")
            break

    if not cases and not issues:
        issues.append("corpus contains no cases")
    if issues:
        raise CorpusError(path, issues)
    return Corpus(path=path, sha256=content_hash(cases), cases=tuple(cases))


def content_hash(cases: Iterable[Case]) -> str:
    """SHA-256 over the cases in canonical form, in file order.

    Independent of line endings, BOM, blank lines and key order, so the same corpus
    hashes identically on Windows (CRLF checkout) and Linux; any change to a case changes it.
    """
    digest = hashlib.sha256()
    for case in cases:
        canonical = json.dumps(
            case.model_dump(mode="json"), sort_keys=True, ensure_ascii=True, separators=(",", ":")
        )
        digest.update(canonical.encode("ascii") + b"\n")
    return digest.hexdigest()
