# Validation

Run from the repository root in a Python 3.12+ virtual environment:

```bash
pytest
python scripts/validate_demo.py
python scripts/analyze_identities.py --json reports/identity-analysis.json
python -m json.tool reports/identity-analysis.json >/dev/null
python -m compileall -q app scripts tests
pip-audit
git diff --check
```

CI repeats tests, compilation, demo validation, CLI analysis, and JSON parsing. Dependency audit and Docker availability are recorded separately because they depend on the validation environment.
