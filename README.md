# Namecheap Domain Scanner Pro

Advanced domain availability scanner with multiple generation modes, scoring, RDAP fallback, batching, and an optional AI-based brandable name generator.

## Features
- Multi-TLD support and batching with adaptive RPM and warm-up
- Generators: lexicographic, phonetic, dictionary, markov, brandable, ai_brandable
- Pronounceability and brand-quality filters, scoring and alerts
- SQLite persistence with resume + RDAP verification fallback
- Priority queue and sharding for parallel workers
- Production logging (human + JSONL)

## Quickstart
1) Create and activate a virtualenv (recommended).
2) Install requirements:
```bash
pip install -r requirements.txt
```
3) Copy `config.yaml` to `config.local.yaml` and fill `api` section with your Namecheap credentials. Keep `sandbox: true` for testing.
4) Run a dry run:
```bash
python scanner.py --config config.local.yaml --dry-run
```

## Configuration
- `config.yaml` is the template; override locally via `config.local.yaml` (ignored by git).
- Key fields:
  - `scanner.mode`: one of `lexicographic`, `phonetic`, `dictionary`, `markov`, `brandable`, `ai_brandable`
  - `scanner.min_length` / `scanner.max_length`: total SLD length window
  - `scanner.prefix` / `scanner.suffix`: fixed edges for the SLD
  - `scanner.batch_size`, `requests_per_minute`, `safety.*`: rate limiting and cool-downs
  - `scanner.db_path`, `scanner.csv_path`: output files

Example (fixed prefix with strict length):
```yaml
scanner:
  tlds: ["com"]
  min_length: 5
  max_length: 5
  prefix: "b"
  mode: "lexicographic"
```

## Running
```bash
python scanner.py --config config.local.yaml
```
Use `--reset-progress` to clear stored progress in the DB for the current space.

## CI
GitHub Actions workflow compiles sources and runs a very small dry-run using `.github/ci.config.yaml`.

## License
MIT. See LICENSE.

