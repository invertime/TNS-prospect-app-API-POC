
--  Création de la base de données

CREATE DATABASE bdd_PPII;
\c bdd_PPII;

--  TABLE : Role
DROP TABLE IF EXISTS Roles;

CREATE TABLE Roles (
    id SERIAL PRIMARY KEY,
    titre VARCHAR(100) NOT NULL,
    description TEXT,
    permissions TEXT
);

DROP TABLE IF EXISTS Utilisateur;

--  TABLE : Utilisateur
CREATE TABLE Utilisateur (
    id SERIAL PRIMARY KEY,
    nom VARCHAR(100) NOT NULL,
    prenom VARCHAR(100) NOT NULL,
    date_de_naissance DATE,
    mot_de_passe VARCHAR(255) NOT NULL
    email VARCHAR(255) UNIQUE NOT NULL,
    numero_telephone VARCHAR(20),
    carte_vitale VARCHAR(50),
    date_creation_compte TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    role_id INT REFERENCES Role(id) ON DELETE SET NULL
);

DROP TABLE IF EXISTS Clients;

--  TABLE : Clients
CREATE TABLE Clients (
    id SERIAL PRIMARY KEY,
    nom VARCHAR(150) NOT NULL,
    adresse TEXT,
    adresse_mail VARCHAR(255) UNIQUE,
    numero_telephone VARCHAR(20),
    secteur VARCHAR(100),
    description TEXT,
    latitude FLOAT,
    longitude FLOAT,
    statut VARCHAR(50) DEFAULT 'prospect',
    date_creation DATE DEFAULT CURRENT_DATE
);

DROP TABLE IF EXISTS Intervenants;

--  TABLE : Intervenants
CREATE TABLE Intervenants (
    id SERIAL PRIMARY KEY,
    id_compte INT REFERENCES Utilisateur(id) ON DELETE CASCADE,
    competences TEXT,
    disponibilite TEXT,
    portfolio TEXT,
    description TEXT,
    documents TEXT
);

DROP TABLE IF EXISTS Competences;

--  TABLE : Competences
CREATE TABLE Competences (
    id SERIAL PRIMARY KEY,
    titre VARCHAR(100) NOT NULL,
    niveau SMALLINT CHECK (niveau BETWEEN 1 AND 5)
);

DROP TABLE IF EXISTS Projets;

--  TABLE : Projets
CREATE TABLE Projets (
    id SERIAL PRIMARY KEY,
    name VARCHAR(150) NOT NULL,
    id_client INT REFERENCES Clients(id) ON DELETE CASCADE,
    statut VARCHAR(50) DEFAULT 'en préparation',
    date_debut DATE,
    date_rendu DATE,
    description TEXT,
    competences TEXT,
    chef_projet INT REFERENCES Intervenants(id) ON DELETE SET NULL
);

DROP TABLE IF EXISTS Intervenants_Projets;

--  TABLE : Intervenants_Projets (relation N:N)
CREATE TABLE Intervenants_Projets (
    id_intervenants INT REFERENCES Intervenants(id) ON DELETE CASCADE,
    id_projets INT REFERENCES Projets(id) ON DELETE CASCADE,
    role_intervenant VARCHAR(100),
    PRIMARY KEY (id_intervenants, id_projets)
);

DROP TABLE IF EXISTS Jalons;

--  TABLE : Jalons
CREATE TABLE Jalons (
    id SERIAL PRIMARY KEY,
    id_projet INT REFERENCES Projets(id) ON DELETE CASCADE,
    date_debut DATE,
    date_fin DATE,
    description TEXT,
    statut VARCHAR(50) CHECK (statut IN ('À faire','En cours','Terminé')),
    responsable INT REFERENCES Intervenants(id) ON DELETE SET NULL
);

DROP TABLE IF EXISTS Projets;

--  TABLE : Messages (Historique interactions)
CREATE TABLE Messages (
    id SERIAL PRIMARY KEY,
    id_staff INT REFERENCES Utilisateur(id) ON DELETE SET NULL,
    id_client INT REFERENCES Clients(id) ON DELETE CASCADE,
    texte TEXT NOT NULL,
    sender INT REFERENCES Utilisateur(id) ON DELETE SET NULL,
    date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    type_message VARCHAR(50) CHECK (type_message IN ('email','appel','reunion','autre'))
);
