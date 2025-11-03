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

class Base(DeclarativeBase):
    pass

class RoleUser(Base):
    __tablename__ = "users_roles"

    id_role: Mapped[int] = mapped_column(ForeignKey("roles.id"), primary_key=True)
    id_user: Mapped[int] = mapped_column(ForeignKey("users.id"), primary_key=True)

    user: Mapped["User"] = relationship(back_populates="roles")
    role: Mapped["Role"] = relationship(back_populates="users")

class Role(Base):
    __tablename__  = 'roles'

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(100))
    description: Mapped[Optional[str]] = mapped_column(Text)
    permissions: Mapped[Optional[str]] = mapped_column(Text)

    users: Mapped[List["RoleUser"]] = relationship(back_populates="role")

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

    def __repr__(self) -> str:
        return f"Role(id={self.id!r}, title={self.title!r}, description={self.description!r}, permissions={self.permissions!r})"

class User(Base):
    __tablename__ = 'users'

    id: Mapped[int] = mapped_column(primary_key=True)
    first_name: Mapped[str] = mapped_column(String(100))
    last_name: Mapped[str] = mapped_column(String(100))
    birth_date: Mapped[Optional[datetime.datetime]]
    password: Mapped[str] = mapped_column(String(255))
    email: Mapped[str] = mapped_column(String(255), unique=True)
    phone: Mapped[Optional[str]] = mapped_column(String(20))
    health_insurance_card: Mapped[Optional[str]] = mapped_column(String(50))
    created_at: Mapped[Optional[datetime.datetime]] = mapped_column(TIMESTAMP, default=datetime.datetime.now())

    roles: Mapped[List["RoleUser"]] = relationship(back_populates="user")

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

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

# helpers

def hash_password(plain_text_password):
    # Hash a password for the first time. Using bcrypt, the salt is saved into the hash itself
    return bcrypt.hashpw(plain_text_password, bcrypt.gensalt())

def check_password_hash(plain_text_password, hashed_password):
    # Check hashed password. Using bcrypt, the salt is saved into the hash itself
    return bcrypt.checkpw(plain_text_password, hashed_password)

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

    birth_date = datetime.datetime.fromtimestamp(int(birth_date))

    if None in [first_name, last_name, birth_date, password, email, phone, health_insurance_card, created_at, role_id] or "" in [first_name, last_name, birth_date, password, email, phone, health_insurance_card, created_at, role_id]:
        return ({'error':"missing field"}, 400)

    session = Session(engine)
    emailQuerry = select(User).where(User.email.__eq__(email))
    emailResp = session.scalar(emailQuerry)
    if not ( emailResp is None ):
        return ({'error': "email already used"}, 403)
    session.close()

    with Session(engine) as session:
        newUser = User(
            first_name=first_name,
            last_name=last_name,
            birth_date=birth_date,
            password=hash_password(password),
            email=email,
            phone=phone,
            health_insurance_card=health_insurance_card,
            created_at = created_at
        )
        session.add(newUser)
        session.commit()


    session = Session(engine)
    idQuerry = select(User.id).where(User.email.__eq__(email))
    id = session.scalar(idQuerry)
    session.close()

    with Session(engine) as session:
        newRoleUser = RoleUser(
            id_role=role_id,
            id_user=id
        )
        session.add(newRoleUser)
        session.commit()

    expires = datetime.timedelta(days=7)
    access_token = create_access_token(identity=str(id), expires_delta=expires)

    return ({'token': access_token}, 201)

@app.route("/API/user/login", methods=["POST"])
def api_login_user():

    email = request.json["email"]
    password = request.json["password"]

    if None in [email, password] or "" in [email, password]:
        return ({'error': 'Missing field'}, 400)

    session=Session(engine)
    idPasswdQuerry = select(User.id, User.password).where(User.email.__eq__(email))
    idPasswd = session.execute(idPasswdQuerry).first()

    if not idPasswd:
        return ({'error': 'User not found'}, 404)

    (id, passwd) = idPasswd

    if not check_password_hash(password.encode(), passwd.encode()):
        return ({'error': 'Wrong password'}, 401)


    expires = datetime.timedelta(days=7)
    access_token = create_access_token(identity=str(id), expires_delta=expires)

    return ({'token': access_token}, 200)

@app.route("/API/user")
def api_user():

    token = request.headers.get("Authorization")

    if (token == ""):
        return ({"msg": "missing token"}, 400)

    token = decode_token(token)
    id = token["sub"]

    session = Session(engine)
    userQuerry = select(User).where(User.id.__eq__(id))
    user = session.scalar(userQuerry)

    return (user.as_dict() if user else {"error": "wrong id"}, 200 if user else 401)

@app.route("/API/roles")
def api_roles():
    session = Session(engine)
    rolesQuerry = select(Role)
    return [user.as_dict() for user in session.scalars(rolesQuerry).all()]

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
