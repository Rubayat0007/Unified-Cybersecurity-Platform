"""Fail when a README cites an id that does not exist in the ledger.

Run in CI so a claim cannot be added without its evidence row.
"""

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
ID_PATTERN = re.compile(r"\b([RE]-[A-Z]+-[A-Za-z0-9-]+)\b")


def ids(path: Path):
    if not path.is_file():
        return set()
    return set(ID_PATTERN.findall(path.read_text(encoding="utf-8")))


readme = ids(REPO / "README.md")
ledger = ids(REPO / "docs" / "ledger.md")

missing = sorted(readme - ledger)

print(f"README ids: {len(readme)}, ledger ids: {len(ledger)}")

if missing:
    print(f"cited but absent from ledger: {missing}", file=sys.stderr)
    raise SystemExit(1)

print("claims trace to ledger rows")
