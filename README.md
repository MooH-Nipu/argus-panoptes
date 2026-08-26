# Argus Panoptes

Local Flask control panel for reviewing and closing upstream alarms from operator-managed whitelist rules.

## Credits

Based on the original [](https://github.com/) by [](https://github.com/). This hardened edition preserves the original upstream reverse-engineering and operator rule workflow, with security controls, dry-run mode, tests, and UI improvements added by Febry Alvian.

## Requirements

- Python 3.9+
- HTTPS upstream origin
- `ARGUS_ALLOWED_ORIGINS` configured as comma-separated exact origins

## Setup

```bash
git clone https://github.com/.git
cd 
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
export ARGUS_ALLOWED_ORIGINS="https://upstream.internal"
python app.py
```

Open `http://127.0.0.1:5000`.

## Safety model

- Browser keeps only opaque local session ID. upstream token stays in server memory.
- Dry-run is default. It fetches, evaluates, and logs candidates without mutation.
- Live mode requires explicit checkbox and confirmation.
- Whitelist rules are operator decisions. Bot does not second-guess alarm names.
- Protect rules override whitelist rules when both match.
- Close cap is mandatory: 1–500 alarms per cycle.
- Suppress fallback is disabled by default and verifies again before use.
- App binds to localhost only. Do not expose it directly to a network.

## Tests and checks

```bash
python -m unittest discover -v
ruff check .
python -m compileall -q app.py config_store.py argus_core.py
pip-audit -r requirements.txt
```

Edit direct dependency pins deliberately. Do not replace `requirements.txt` with `pip freeze` output.
