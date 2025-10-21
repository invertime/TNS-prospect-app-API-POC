import sqlite3
from flask import (
    Flask,
    g,
    request,
    redirect,
    render_template,
    abort
)
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    login_required
)
import bcrypt

app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)

app.secret_key = b"secret_key"

# Database

DATABASE='../database/db.db'

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('../database/schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

def get_db():
    db=getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.teardown_appcontext
def close_connection(exeption):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# helpers

def hash_password(plain_text_password):
    # Hash a password for the first time
    #   (Using bcrypt, the salt is saved into the hash itself)
    return bcrypt.hashpw(plain_text_password, bcrypt.gensalt())

def check_password_hash(plain_text_password, hashed_password):
    # Check hashed password. Using bcrypt, the salt is saved into the hash itself
    return bcrypt.checkpw(plain_text_password, hashed_password)

# User

class User(UserMixin):
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

def find_user(id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        """
        SELECT *
        FROM users
        WHERE id=?;
        """,
        (id,),
    )
    user = cursor.fetchone()
    if user is None:
        return None
    return User(id=id, username=user[1], password=user[2], role=user[3], nom=user[4], prenom=user[5])

@login_manager.user_loader
def load_user(user_id):
    return find_user(user_id)

@app.route("/")
def home():
    return "Hello world !"

@app.route("/user/register", methods=["GET"])
def register_user_view():
    return render_template(
        "register.html"
    )


@app.route("/user/login", methods=["GET"])
def login_user_view():
    return render_template(
        "login.html"
    )

@app.route("/dashboard", methods=["GET"])
@login_required
def dashboard_view():
    return render_template(
        "dashboard.html"
    )

@app.route("/API/user/register", methods=["POST"])
def api_register_user():

    username = request.form["username"]
    password = request.form["password"]
    role = request.form["role"]
    nom = request.form["nom"]
    prenom = request.form["prenom"]

    if None in [username, password, role, nom, prenom] or "" in [username, password, role, nom, prenom]:
        return "missing field"

    db = get_db()
    cursor = db.cursor()

    cursor.execute(
        """
        INSERT INTO users (username, password, role, nom, prenom)
        VALUES (?,?,?,?,?)
        """,
        (username, hash_password(password), role, nom, prenom)
    )

    db.commit()

    return redirect("/user/login")

@app.route("/API/user/login", methods=["POST"])
def api_login_user():

    username = request.form["username"]
    password = request.form["password"]

    if None in [username, password] or "" in [username, password]:
        return "missing field"

    db = get_db()
    cursor = db.cursor()

    cursor.execute(
        """
        SELECT password
        FROM users
        WHERE username = ?;
        """,
        (username,)
    )

    passwd = cursor.fetchone()

    if passwd is None:
        return redirect("/user/login?error=Incorrect username")

    if not check_password_hash(password.encode(), passwd[0].encode()):
        return redirect("/user/login?error=Wrong password")

    cursor.execute(
        """
        SELECT *
        FROM users
        WHERE username = ?;
        """,
        (username,)
    )

    user = cursor.fetchone()
    if user is None:
        return None
    user = User(id=user[0], username=user[1], password=user[2], role=user[3], nom=user[4], prenom=user[5])

    app.logger.info(user.id)

    login_user(user)

    return redirect("/dashboard")

@app.route("/API/user/logout")
@login_required
def logout():
    logout_user()
    return redirect("/?error=Logout successfully")
