from flask import (
    Flask,
    g,
    request,
    jsonify
)
import bcrypt
from flask_jwt_extended import create_access_token, JWTManager, decode_token
import datetime # TODO: Only import what's matter
from flask_cors import CORS

from sqlalchemy import ForeignKey, create_engine, String, Text, TIMESTAMP, text, select
from sqlalchemy.engine import URL
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, Session
from typing import List, Optional

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


url = URL.create(
    drivername="postgresql",
    username=DB_USER,
    password=DB_PASSWORD,
    host=DB_HOST,
    port=DB_PORT,
    database=DB_NAME
)

engine = create_engine(url, echo=True)

# def init_db():
#     with app.app_context():
#         db = get_conn()
#         with app.open_resource('../database/schema.sql', mode='r') as f:
#             db.cursor().execute(f.read())
#         db.commit()

# def get_conn():
#     conn=getattr(g, '_database', None)
#     if conn is None:
#         conn = g._database = engine.connect()
#     return conn

# @app.teardown_appcontext
# def close_connection(exeption):
#     db = getattr(g, '_database', None)
#     if db is not None:
#         db.close()

class Base(DeclarativeBase):
    pass

class Role(Base):
    __tablename__  = 'role'

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(100))
    description: Mapped[Optional[str]] = mapped_column(Text)
    permissions: Mapped[Optional[str]] = mapped_column(Text)

    users: Mapped[List["User"]] = relationship(
        back_populates="role"
    )

    def __repr__(self) -> str:
        return f"Role(id={self.id!r}, title={self.title!r}, description={self.description!r}, permissions={self.permissions!r})"

class User(Base):
    __tablename__ = 'user'

    id: Mapped[int] = mapped_column(primary_key=True)
    first_name: Mapped[str] = mapped_column(String(100))
    last_name: Mapped[str] = mapped_column(String(100))
    birth_date: Mapped[Optional[datetime.datetime]]
    password: Mapped[str] = mapped_column(String(255))
    email: Mapped[str] = mapped_column(String(255), unique=True)
    phone: Mapped[Optional[str]] = mapped_column(String(20))
    health_insurance_card: Mapped[Optional[str]] = mapped_column(String(50))
    created_at: Mapped[Optional[datetime.datetime]] = mapped_column(TIMESTAMP, default=datetime.datetime.now())
    role_id: Mapped["id"] = mapped_column(ForeignKey("role.id"))

    role: Mapped["Role"] = relationship(back_populates="users")

    def __repr__(self) -> str:
        return f"""
            User(
                id={self.id!r},
                first_name={self.first_name!r},
                birth_date={self.birth_date!r},
                password={self.password!r},
                email={self.email!r},
                phone={self.phone!r},
                health_insurance_card={self.health_insurance_card!r},
                created_at={self.created_at!r}
            )
        """

# Base.metadata.create_all(engine)

# helpers

def hash_password(plain_text_password):
    # Hash a password for the first time. Using bcrypt, the salt is saved into the hash itself
    return bcrypt.hashpw(plain_text_password, bcrypt.gensalt())

def check_password_hash(plain_text_password, hashed_password):
    # Check hashed password. Using bcrypt, the salt is saved into the hash itself
    return bcrypt.checkpw(plain_text_password, hashed_password)

# User

class User_old(): # TODO: remove this class
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
    db = get_conn()
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
    return User_old(id=id, username=user[1], password=user[2], role=user[3], nom=user[4], prenom=user[5])

# Displayed routes

@app.route("/")
def home():
    return "Hello world !"

# API routes

@app.route("/API/canRegister")
def api_canregister():
    return app.config["CAN_REGISTER"]

@app.route("/API/user/register", methods=["POST"])
def api_register_user():

    first_name = request.json["first_name"]
    last_name = request.json["last_name"]
    birth_date = request.json["birth_date"]
    password = request.json["password"]
    email = request.json["email"]
    phone = request.json["phone"]
    health_insurance_card = request.json["health_insurance_card"]
    created_at = datetime.datetime.fromtimestamp( round(datetime.datetime.now().timestamp()) / 1e3)
    role_id = request.json["role_id"]

    if None in [first_name, last_name, birth_date, password, email, phone, health_insurance_card, created_at, role_id] or "" in [first_name, last_name, birth_date, password, email, phone, health_insurance_card, created_at, role_id]:
        return ({'error':"missing field"}, 400)

    session = Session(engine)
    emailQuerry = select(User).where(User.email.__eq__(email))
    emailResp = session.scalar(emailQuerry)
    if (not ( emailResp is None )):
        return ({'error': "email already used"}, 403)
    session.close()

    with Session(engine) as session:
        newUser = User(
            first_name=first_name,
            last_name=last_name,
            birth_date=birth_date,
            password=password,
            email=email,
            phone=phone,
            health_insurance_card=health_insurance_card,
            created_at = created_at,
            role_id = role_id
        )
        session.add(newUser)
        session.commit()


    session = Session(engine)
    idQuerry = select(User.id).where(User.email.__eq__(email))
    id = session.scalar(idQuerry)
    session.close()

    expires = datetime.timedelta(days=7)
    access_token = create_access_token(identity=str(id), expires_delta=expires)

    return ({'token': access_token}, 201)

@app.route("/API/user/login", methods=["POST"])
def api_login_user():

    email = request.json["email"]
    password = request.json["password"]

    if None in [email, password] or "" in [email, password]:
        return ({'error': 'Missing field'}, 400)

    conn = get_conn()

    passwd_res = conn.execute(text("SELECT password FROM users WHERE email = :email "), {"email": email})

    passwd = passwd_res[0].password

    if passwd is None:
        return ({'error': 'User not found'}, 404)

    if not check_password_hash(password.encode(), passwd[0].encode()):
        return ({'error': 'Wrong password'}, 401)

    conn.execute(
        """
        SELECT *
        FROM users
        WHERE email = %s
        """,
        (email,)
    )

    # TODO: Only one db request

    user = conn.fetchone()
    if user is None:
        return None

    user = User_old(id=user[0], username=user[1], password=user[2], role=user[3], nom=user[4], prenom=user[5])

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

@app.route("/API/roles")
def api_roles():
    db = get_conn()
    cursor = db.cursor(cursor_factory=RealDictCursor)

    cursor.execute(
        """
        SELECT *
        FROM roles
        """
    )

    return cursor.fetchall()


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

# if __name__ == "__main__":
#     app.run(port=8000, debug=True)
