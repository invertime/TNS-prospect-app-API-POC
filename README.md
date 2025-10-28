# TNS POC

This API is just a POC for the TNS prospection project (PP2I TNCY)

The API is a REST API

## Libraries/Frameworks used

- Flask
- flask_jwt_extended (To handle jwt tokens)
- flask_cors (To handle cors)
- Bcrypt (To hash password and handle them)
- psycopg2 (To handle the connection to the PostgresSql Database)

## How to run the app

Debug mode :

```bash
python -m venv .venv
source ./.venv/bin/activate
pip install -r requirements.txt
export ENV_FILE_LOCATION=../.env
python -m flask
```

Run in production :

```
docker-compose up
```
