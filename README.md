# TNS POC

This web application is just a POC for the TNS project (PP2I TNCY)

## How to run the app

Debug mode :

```bash
python -m venv .venv
source ./.venv/bin/activate
pip install -r requirements.txt
python3 src/__init__.py
```

To init an empty db with tables from schema.sql:

```bash
sqlite3 database/db.db "VACUUM;"
cd src
python
from __init__.py import init_db
init_db()
```
