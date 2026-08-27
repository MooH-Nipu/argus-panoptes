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
git clone https://github.com/MooH-Nipu/argus-panoptes.git
cd argus-panoptes
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
export ARGUS_ALLOWED_ORIGINS="https://upstream.internal"
python app.py
```

Open `http://127.0.0.1:5000`.

## Docker / LAN review

```bash
cp .env.example .env
# Edit ARGUS_ALLOWED_ORIGINS and set BIND_IP to this server's LAN IP.
# Set HOST_UID/HOST_GID from: id -u; id -g
docker compose up -d --build
```

If upstream uses a self-signed certificate, prefer `ARGUS_CA_BUNDLE`. For a trusted internal-only deployment without a CA file, set `ARGUS_TLS_INSECURE=true` in `.env`; this disables certificate verification only for upstream requests.

From another PC on the same trusted LAN, open `http://<BIND_IP>:<PORT>`.

Default Compose binding is `127.0.0.1`; LAN access requires an explicit `BIND_IP`. Avoid `0.0.0.0` unless exposing every interface is intentional.

Runtime configuration lives in the Compose `config_data` volume. Back it up with:

```bash
docker compose exec app tar -C /data -czf /tmp/argus-config.tgz .
docker compose cp app:/tmp/argus-config.tgz ./argus-config.tgz
```

## Safety model

- Browser keeps only opaque local session ID. upstream token stays in server memory.
- Dry-run is default. It fetches, evaluates, and logs candidates without mutation.
- Live mode requires explicit checkbox and confirmation.
- Whitelist starts empty; operators add rules manually one by one through Rules UI.
- Automation rules can submit `False Positive` or `Exclusion`; rules without disposition default to `False Positive`.
- `Exclusion` uses the captured three-argument upstream action payload and never enters suppress fallback.
- Protect rules override whitelist rules when both match.
- Close cap is mandatory: 1–500 alarms per cycle.
- Suppress fallback is disabled by default and verifies again before use.
- Docker binds only to configured `BIND_IP`. Keep that address on trusted LAN; never use public or guest-facing interface.

## Distribution status

Internal deployment is supported on a trusted, isolated LAN after upstream origin configuration. HTTP is intentionally supported for low-friction internal use; do not expose it to guest Wi-Fi, the internet, or untrusted networks. Public redistribution is not authorized by this repository: upstream `` had no license when this derivative was created. Obtain an explicit license or written permission before making this repository public.

## Tests and checks

```bash
python -m unittest discover -v
ruff check . --select F,E9,BLE,RUF100
bandit -q -r app.py config_store.py argus_core.py
python -m compileall -q app.py config_store.py argus_core.py
pip-audit -r requirements.txt
ARGUS_ALLOWED_ORIGINS=https://upstream.example.internal docker compose config
```

Edit direct dependency pins deliberately. Do not replace `requirements.txt` with `pip freeze` output.
