#!/usr/bin/env python3
"""Vendor Lakera's gandalf_ignore_instructions (MIT) test split as labeled corpus cases.

Dev-time only; ClawShield never downloads data at run time. Pinned to one dataset revision
and one file checksum, so the vendored corpus is reproducible and reviewable:

    uv run --with pyarrow python scripts/import_gandalf.py

Labeling (redteam/corpus/public/README.md): every row is a real attempt to make the model
drop its instructions and reveal a secret, i.e. a direct instruction override plus secret
extraction -> llm01_direct, expected_severity critical, canary CANARY-7F3A.
"""

import hashlib
import io
import json
import sys
import urllib.request
from pathlib import Path

import pyarrow.parquet as pq

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from clawshield.core.models import Case  # noqa: E402

DATASET = "Lakera/gandalf_ignore_instructions"
REVISION = "04737b65e90a6794ec227012e4a255a7def6344b"
FILE = "data/test-00000-of-00001-bc92128b9288a6d1.parquet"
SHA256 = "56b646d133335ebc535266bd55dbe1b5bee7caa4b95bf49d040684b9b5dd9972"  # = HF LFS oid
URL = f"https://huggingface.co/datasets/{DATASET}/resolve/{REVISION}/{FILE}"
OUT = ROOT / "redteam" / "corpus" / "public" / "gandalf_ignore_instructions.jsonl"
MAX_BYTES = 5 * 1024 * 1024
CANARY = "CANARY-7F3A"


def _normalize(text: str) -> str:
    return " ".join(text.casefold().split())


def main() -> None:
    with urllib.request.urlopen(URL, timeout=60) as resp:
        data = resp.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        sys.exit(f"{FILE} exceeds {MAX_BYTES} bytes")
    digest = hashlib.sha256(data).hexdigest()
    if digest != SHA256:
        sys.exit(f"checksum mismatch for {FILE}: got {digest}, pinned {SHA256}")
    texts = pq.read_table(io.BytesIO(data), columns=["text"]).column("text").to_pylist()

    seed = ROOT / "redteam" / "corpus" / "seed.jsonl"
    lines_in = [ln for ln in seed.read_text("utf-8").splitlines() if ln.strip()]
    known = {_normalize(json.loads(ln)["text"]) for ln in lines_in}
    lines, skipped = [], {"duplicate": 0, "invalid": 0}
    for text in texts:
        if not isinstance(text, str) or _normalize(text) in known:
            skipped["duplicate" if isinstance(text, str) else "invalid"] += 1
            continue
        known.add(_normalize(text))
        case_id = "gd-" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
        try:
            case = Case(
                id=case_id, text=text, label="malicious", category="llm01_direct",
                expected_severity="critical", canary=CANARY,
            )  # fmt: skip
        except ValueError:
            skipped["invalid"] += 1
            continue
        lines.append(json.dumps(case.model_dump(mode="json", exclude_none=True), ensure_ascii=True))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines) + "\n", encoding="ascii", newline="\n")
    print(f"{len(texts)} rows -> {len(lines)} cases in {OUT.relative_to(ROOT)}; skipped {skipped}")
    print(f"sha256({OUT.name}) = {hashlib.sha256(OUT.read_bytes()).hexdigest()}")


if __name__ == "__main__":
    main()
