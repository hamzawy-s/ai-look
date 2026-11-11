# AI Look

AI-augmented web application security platform scaffold.

## Architecture

- `core_engine.py`: all core models, scope, deduplication, adaptive controls, signatures, risk, coverage, persistence, AI analysis, and finding pipeline.
- `adapters/`: integration points for SAST, dependency analysis, dynamic testing, browser crawling, and regression scheduling.
- `reporting/`: JSON and CSV export starter.
- `notification/`: in-process event bus starter.
- `website/` and `mobile/`: frontend placeholders.
- `tests/`: unit and integration test locations.

## Setup

```powershell
python -m venv .venv
.venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
python -m unittest discover -s tests
python main.py
```

## Important

Adapter files are integration interfaces, not completed vulnerability scanners. Implement and validate each adapter against explicitly authorized targets. Configure scope enforcement before running scans. AI output is advisory and must not alter deterministic finding evidence, severity, or lifecycle state.
