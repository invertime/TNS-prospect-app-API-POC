from flask import (
    Flask,
    g,
    request,
    jsonify
)
import bcrypt
from flask_jwt_extended import create_access_token, JWTManager, decode_token
import datetime
from flask_cors import CORS
import psycopg2

app = Flask(__name__)
CORS(app)
app.config.from_envvar('ENV_FILE_LOCATION')

app.secret_key = app.config["JWT_SECRET_KEY"];

jwt = JWTManager(app)

# Database

DB_NAME=getattr(app.config, "DB_NAME", "pp2i1")
DB_USER=app.config["DB_USER"]
DB_PASSWORD=app.config["DB_PASSWORD"]
DB_HOST=getattr(app.config, "DB_HOST", "localhost")
DB_PORT=getattr(app.config, "DB_PORT", 5432)

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('../database/schema.sql', mode='r') as f:
            db.cursor().execute(f.read())
        db.commit()

def get_db():
    db=getattr(g, '_database', None)
    if db is None:
        db = g._database = psycopg2.connect(f"dbname={DB_NAME} user={DB_USER} password={DB_PASSWORD} host={DB_HOST} port={DB_PORT}")
    return db

@app.teardown_appcontext
def close_connection(exeption):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# helpers

def hash_password(plain_text_password):
    # Hash a password for the first time. Using bcrypt, the salt is saved into the hash itself
    return bcrypt.hashpw(plain_text_password, bcrypt.gensalt())

def check_password_hash(plain_text_password, hashed_password):
    # Check hashed password. Using bcrypt, the salt is saved into the hash itself
    return bcrypt.checkpw(plain_text_password, hashed_password)

# User

class User():
    def __init__(
        self,
        id: int,
        username: str,
        password: bytes,
        role: str,
        nom: str,
        prenom: str
    ):
        self.id = id
        self.username = username
        self.password = password
        self.role = role
        self.nom = nom
        self.prenom = prenom

def find_user(id: int):
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        """
        SELECT *
        FROM users
        WHERE id=%s
        """,
        (id,),
    )
    user = cursor.fetchone()
    if user is None:
        return None
    return User(id=id, username=user[1], password=user[2], role=user[3], nom=user[4], prenom=user[5])

# Displayed routes

@app.route("/")
def home():
    return "Hello world !"

# API routes

@app.route("/API/user/register", methods=["POST"])
def api_register_user():

    username = request.json["username"]
    password = request.json["password"]
    role = request.json["role"]
    nom = request.json["nom"]
    prenom = request.json["prenom"]

    if None in [username, password, role, nom, prenom] or "" in [username, password, role, nom, prenom]:
        return ({'error':"missing field"}, 400)

    db = get_db()
    cursor = db.cursor()

    cursor.execute(
        """
        INSERT INTO users (username, password, role, nom, prenom)
        VALUES (%s,%s,%s,%s,%s)
        """,
        (username, hash_password(password), role, nom, prenom)
    )

    db.commit()

    id = cursor.lastrowid

    expires = datetime.timedelta(days=7)
    access_token = create_access_token(identity=str(id), expires_delta=expires)

    return ({'token': access_token}, 201)

@app.route("/API/user/login", methods=["POST"])
def api_login_user():

    username = request.json["username"]
    password = request.json["password"]

    if None in [username, password] or "" in [username, password]:
        return ({'error': 'Missing field'}, 400)

    db = get_db()
    cursor = db.cursor()

    cursor.execute(
        """
        SELECT password
        FROM users
        WHERE username = %s
        """,
        (username,)
    )

    passwd = cursor.fetchone()

    if passwd is None:
        return ({'error': 'User not found'}, 404)

    if not check_password_hash(password.encode(), passwd[0].encode()):
        return ({'error': 'Wrong password'}, 401)

    cursor.execute(
        """
        SELECT *
        FROM users
        WHERE username = %s
        """,
        (username,)
    )

    user = cursor.fetchone()
    if user is None:
        return None

    user = User(id=user[0], username=user[1], password=user[2], role=user[3], nom=user[4], prenom=user[5])

    app.logger.info(user.id)

    expires = datetime.timedelta(days=7)
    access_token = create_access_token(identity=str(user.id), expires_delta=expires)

    return ({'token': access_token}, 200)

@app.route("/API/user")
def api_user():

    token = request.headers.get("Authorization")

    if (token == ""):
        return ({"msg": "missing token"}, 400)

    token = decode_token(token)

    app.logger.info(token["sub"])

    user = find_user(token["sub"])

    return (jsonify(None if user is None else user.__dict__), 200 if user else 401)

@app.route("/API/client/create", methods=["POST"])
def api_create_client():
    pass
@app.route("/API/client/read/<int:id>", methods=["POST"])
def api_read_client(id):
    pass
@app.route("/API/client/update", methods=["POST"])
def api_update_client():
    pass
@app.route("/API/client/delete", methods=["POST"])
def api_delete_client():
    pass

if __name__ == "__main__":
    app.run(port=8000, debug=True)
