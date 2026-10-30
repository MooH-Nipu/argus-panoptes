# Argus Panoptes

Local Flask control panel for reviewing and closing upstream alarms from operator-managed whitelist rules.

## Credits

Based on the original [](https://github.com/) by [](https://github.com/). This hardened edition preserves the original upstream reverse-engineering and operator rule workflow, with security controls, dry-run mode, tests, and UI improvements added by Febry Alvian.

## Requirements

- Python 3.9+
- HTTPS upstream origin using a private IP literal

## Setup

```bash
git clone https://github.com/MooH-Nipu/argus-panoptes.git
cd argus-panoptes
python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip setuptools
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.

upstream certificate verification is disabled in source because supported upstream servers use internal self-signed certificates. Login targets remain restricted to private IP literals over HTTPS.

## Docker / LAN review

```bash
cp .env.example .env
# Set BIND_IP to this server's LAN IP.
# Set HOST_UID/HOST_GID from: id -u; id -g
docker compose up -d --build
```

From another PC on the same trusted LAN, open `http://<BIND_IP>:<PORT>`.

Default Compose binding is `127.0.0.1`; LAN access requires an explicit `BIND_IP`. Avoid `0.0.0.0` unless exposing every interface is intentional.

Runtime configuration lives in the Compose `config_data` volume. Back it up with:

```bash
docker compose exec app tar -C /data -czf /tmp/argus-config.tgz .
docker compose cp app:/tmp/argus-config.tgz ./argus-config.tgz
```

## Safety model

- Browser keeps only opaque local session ID. upstream token stays in server memory.
- upstream origin follows validated login input dynamically; only private IPv4/IPv6 HTTPS targets are accepted. Hostnames are rejected to prevent DNS rebinding.
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

Internal deployment is supported on a trusted, isolated LAN. HTTP is intentionally supported for the local control panel; upstream upstream remains HTTPS-only. Do not expose it to guest Wi-Fi, the internet, or untrusted networks. Public redistribution is not authorized by this repository: upstream `` had no license when this derivative was created. Obtain an explicit license or written permission before making this repository public.

## Tests and checks

```bash
python -m unittest discover -v
ruff check . --select F,E9,BLE,RUF100
bandit -q -r app.py config_store.py argus_core.py
python -m compileall -q app.py config_store.py argus_core.py
pip-audit -r requirements.txt
docker compose config
```

Edit direct dependency pins deliberately. Do not replace `requirements.txt` with `pip freeze` output.
