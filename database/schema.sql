-- Drop existing tables

DROP TABLE IF EXISTS Roles CASCADE;
DROP TABLE IF EXISTS Users CASCADE;
DROP TABLE IF EXISTS Clients CASCADE;
DROP TABLE IF EXISTS Workers CASCADE;
DROP TABLE IF EXISTS Skills CASCADE;
DROP TABLE IF EXISTS Projects CASCADE;
DROP TABLE IF EXISTS Workers_Projects CASCADE;
DROP TABLE IF EXISTS Milestones CASCADE;
DROP TABLE IF EXISTS Messages CASCADE;

--  TABLE : Role

CREATE TABLE Roles (
    id SERIAL PRIMARY KEY,
    title VARCHAR(100) NOT NULL,
    description TEXT,
    permissions TEXT
);

--  TABLE : Users

CREATE TABLE Users (
    id SERIAL PRIMARY KEY,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    birth_date DATE,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    phone VARCHAR(20),
    health_insurance_card VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
--  TABLE : Users_Roles (relation N:N)

CREATE TABLE Users_Roles (
    id_user INT REFERENCES Users(id) ON DELETE CASCADE,
    id_role INT REFERENCES  Roles(id) ON DELETE CASCADE,
    PRIMARY KEY(id_user,id_role)
)

--  TABLE : Clients

CREATE TABLE Clients (
    id SERIAL PRIMARY KEY,
    name VARCHAR(150) NOT NULL,
    adress TEXT,
    email VARCHAR(255) UNIQUE,
    phone VARCHAR(20),
    area VARCHAR(100),
    description TEXT,
    latitude FLOAT,
    longitude FLOAT,
    status VARCHAR(50) DEFAULT 'prospect',
    created_at DATE DEFAULT CURRENT_DATE
);

--  TABLE : Workers

CREATE TABLE Workers (
    id SERIAL PRIMARY KEY,
    id_account INT REFERENCES Users(id) ON DELETE CASCADE,
    availability TEXT,
    portfolio TEXT,
    description TEXT,
    documents TEXT
);

--  TABLE : Skills

CREATE TABLE Skills (
    id SERIAL PRIMARY KEY,
    title VARCHAR(100) NOT NULL
);

--  TABLE : Projets

CREATE TABLE Projects (
    id SERIAL PRIMARY KEY,
    name VARCHAR(150) NOT NULL,
    id_client BIGINT REFERENCES Clients(id) ON DELETE CASCADE,
    status VARCHAR(50) DEFAULT 'en préparation',
    begin_date DATE,
    due_date DATE,
    description TEXT,
    id_project_manager INT REFERENCES Workers(id) ON DELETE SET NULL
);

--  TABLE : Workers_Projects (relation N:N)

CREATE TABLE Workers_Projects (
    id_worker INT REFERENCES Workers(id) ON DELETE CASCADE,
    id_project INT REFERENCES Projects(id) ON DELETE CASCADE,
    role_worker VARCHAR(100),
    PRIMARY KEY (id_worker, id_project)
);
--  TABLE : Skills_Projects (relation N:N)

CREATE TABLE Skills_Projects (
    id_skill INT REFERENCES Skills(id) ON DELETE CASCADE,
    id_project INT REFERENCES Projects(id) ON DELETE CASCADE,
    level INT,
    PRIMARY KEY (id_skill, id_project)
);

--  TABLE : Skills_Workers (relation N:N)

CREATE TABLE Skills_workers (
    id_worker INT REFERENCES Workers(id) ON DELETE CASCADE,
    id_skill INT REFERENCES Skills(id) ON DELETE CASCADE,
    level INT,
    PRIMARY KEY (id_worker, id_skill)
);



--  TABLE : Jalons

CREATE TABLE Milestones (
    id SERIAL PRIMARY KEY,
    id_project INT REFERENCES Projects(id) ON DELETE CASCADE,
    begin_date DATE,
    end_date DATE,
    description TEXT,
    status VARCHAR(50) CHECK (status IN ('A faire','En cours','Terminé')),
    id_     manager INT REFERENCES Workers(id) ON DELETE SET NULL
);


--  TABLE : Messages (Historique interactions)

CREATE TABLE Messages (
    id SERIAL PRIMARY KEY,
    id_staff INT REFERENCES Users(id) ON DELETE SET NULL,
    id_client INT REFERENCES Clients(id) ON DELETE CASCADE,
    text TEXT NOT NULL,
    sender INT REFERENCES Users(id) ON DELETE SET NULL,
    date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    message_type VARCHAR(50) CHECK (message_type IN ('email','appel','reunion','autre'))
);
