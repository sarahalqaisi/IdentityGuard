# Contributing

Contributions that improve defensive identity analysis, validation, documentation, accessibility, or test quality are welcome.

1. Open an issue describing the behavior and security assumptions.
2. Create a focused branch and include tests for behavior changes.
3. Use only synthetic identities, authentication activity, IP addresses, and organizations.
4. Run `pytest`, demo validation, compilation, and `git diff --check`.
5. Document rule semantics, risk-weight changes, and limitations.

Do not submit real credentials, employee records, provider exports, offensive credential tooling, or claims unsupported by reproducible evidence. New dependencies should be minimal, pinned, justified, and audited.
