CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY NOT NULL
        CHECK (length(CAST(username AS BLOB)) BETWEEN 1 AND 64),
    salt BLOB NOT NULL CHECK (length(salt) = 16),
    password_hash BLOB NOT NULL CHECK (length(password_hash) = 32),
    failures INTEGER NOT NULL DEFAULT 0 CHECK (failures BETWEEN 0 AND 5),
    locked INTEGER NOT NULL DEFAULT 0 CHECK (locked IN (0, 1)),
    CHECK (locked = (failures >= 5))
);

CREATE TABLE IF NOT EXISTS ip_limits (
    ip TEXT PRIMARY KEY NOT NULL,
    started INTEGER NOT NULL,
    attempts INTEGER NOT NULL CHECK (attempts BETWEEN 1 AND 20)
);
