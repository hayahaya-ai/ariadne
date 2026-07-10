# Contributing

Thanks for contributing to Ariadne.

## Development

Prerequisites:

- Go 1.26 or newer
- `make`

Run the full local check:

```bash
make check
```

Build:

```bash
make build
```

## Design Rules

- Keep deterministic collection separate from classification.
- Do not execute agent runtimes, tool servers, package managers, or network calls in deterministic mode.
- Do not emit secret values.
- Add or update validation scenarios for every new exposure family.
- Prefer typed facts and graph edges over free-form findings.
- Return `inconclusive` when evidence is missing.

## Pull Requests

A good PR should include:

- a clear summary
- tests or validation scenarios
- documentation updates for user-visible behavior
- notes about privacy, redaction, and compatibility impact

## Adding Runtime Support

New adapters should define:

- surfaces discovered
- parse versus summarize behavior
- authorities created
- controls recognized
- boundaries modeled
- validation scenarios
