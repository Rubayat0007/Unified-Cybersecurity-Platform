# Release checklist

Run before tagging a release. Each step names what "pass" looks like; a step
that cannot run is a decision, not a silent skip.

## 1. Working tree

```powershell
git status --short     # expect empty
git log --oneline -1   # note the commit for the tag message
```

## 2. Static checks

```powershell
python -m compileall -q api core adapters tools
```

## 3. Test suites

```powershell
python -m unittest discover -s tests/unit -p "test_*.py"
python -m unittest discover -s tests/integration -p "test_*.py"
```

Expected: `OK` from both (179 unit, 35 integration as of v0.2.1).

## 4. Live end-to-end

Requires the PhishVision runtime (torch, EasyOCR, provisioned checkpoint).

```powershell
python scripts/smoke_live.py
```

Expected: ten `PASS` lines and `RESULT: PASS`; exit `0`. Exit `2` means a
prerequisite is missing — record which one; do not tag as verified.

What it exercises that the suites cannot: uvicorn → `/v1/assess/image` →
worker subprocess JSON-lines protocol → OCR + CNN → adapter → correlation →
decision, plus the `422` path for invalid bytes.

## 5. Contract spot-check

Confirm `docs/api-contract.md` still matches behaviour. Any behavioural change
in this release means the contract document must change in the same commit.

## 6. Tag

```powershell
git tag -a vX.Y.Z -m "what was verified and how"
git push origin main
git push origin vX.Y.Z
```

The tag message should say what was run, not just what changed.

## Known limits

- The live smoke is not in CI: it needs torch, EasyOCR, and a 103 MB checkpoint.
  It is a pre-release gate a human runs.
- Integration tests do not start a real worker; they use fixtures. The smoke
  script is the only check that runs the actual subprocess.
- No authentication exists; the service is loopback-only by design. A release
  does not change that.
