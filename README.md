# TNS POC

This web application is just a POC for the TNS project (PP2I TNCY)

## How to run the app

Debug mode :

```bash
python -m venv .venv
source ./.venv/bin/activate
pip install -r requirements.txt
python3 -m flask --app=src/app.py run --port=8000 --debug
```

To init an empty db:

```bash
sqlite3 database/db.db "VACUUM;"
```
