CREATE TABLE users (
    username      TEXT PRIMARY KEY,
    email         TEXT NOT NULL DEFAULT '',
    name          TEXT NOT NULL DEFAULT '',
    groups        TEXT NOT NULL DEFAULT '[]',
    role          TEXT NOT NULL DEFAULT 'user',
    created_at    TEXT NOT NULL DEFAULT '',
    last_login_at TEXT NOT NULL DEFAULT ''
);

CREATE TABLE devices (
    id              TEXT PRIMARY KEY,
    username        TEXT NOT NULL DEFAULT '',
    platform        TEXT NOT NULL DEFAULT '',
    serial_number   TEXT NOT NULL DEFAULT '',
    model           TEXT NOT NULL DEFAULT '',
    device_name     TEXT NOT NULL DEFAULT '',
    os_version      TEXT NOT NULL DEFAULT '',
    status          TEXT NOT NULL DEFAULT '',
    user_channel_id TEXT NOT NULL DEFAULT '',
    enrolled_at     TEXT NOT NULL DEFAULT '',
    last_seen_at    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX devices_username ON devices (username);

CREATE TABLE profiles (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL DEFAULT '',
    description   TEXT NOT NULL DEFAULT '',
    platforms     TEXT NOT NULL DEFAULT '[]',
    macos_channel TEXT NOT NULL DEFAULT '',
    assignment    TEXT NOT NULL DEFAULT '{}',
    template      TEXT NOT NULL DEFAULT '',
    source        TEXT NOT NULL DEFAULT '',
    updated_at    TEXT NOT NULL DEFAULT ''
);

-- No foreign keys: DeleteProfile deliberately leaves rows here for the
-- reconciler, and DeleteDevice removes them explicitly.
CREATE TABLE device_profiles (
    device_id    TEXT NOT NULL,
    profile_id   TEXT NOT NULL,
    state        TEXT NOT NULL DEFAULT '',
    channel      TEXT NOT NULL DEFAULT '',
    identifier   TEXT NOT NULL DEFAULT '',
    content_hash TEXT NOT NULL DEFAULT '',
    command_uuid TEXT NOT NULL DEFAULT '',
    detail       TEXT NOT NULL DEFAULT '',
    updated_at   TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (device_id, profile_id)
);
CREATE INDEX device_profiles_profile ON device_profiles (profile_id);
CREATE INDEX device_profiles_command ON device_profiles (command_uuid);

CREATE TABLE commands (
    uuid         TEXT PRIMARY KEY,
    device_id    TEXT NOT NULL DEFAULT '',
    channel      TEXT NOT NULL DEFAULT '',
    request_type TEXT NOT NULL DEFAULT '',
    profile_id   TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL DEFAULT '',
    detail       TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL DEFAULT '',
    updated_at   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX commands_device ON commands (device_id, created_at);

CREATE TABLE enrollments (
    token         TEXT PRIMARY KEY,
    challenge     TEXT NOT NULL,
    username      TEXT NOT NULL DEFAULT '',
    created_by    TEXT NOT NULL DEFAULT '',
    created_at    TEXT NOT NULL DEFAULT '',
    expires_at    TEXT NOT NULL DEFAULT '',
    downloaded_at TEXT,
    used_at       TEXT
);
CREATE UNIQUE INDEX enrollments_challenge ON enrollments (challenge);

CREATE TABLE issued_certs (
    serial      TEXT PRIMARY KEY,
    common_name TEXT NOT NULL DEFAULT '',
    username    TEXT NOT NULL DEFAULT '',
    sha256      TEXT NOT NULL DEFAULT '',
    pem         TEXT NOT NULL DEFAULT '',
    not_after   TEXT NOT NULL DEFAULT '',
    issued_at   TEXT NOT NULL DEFAULT '',
    revoked_at  TEXT
);
CREATE INDEX issued_certs_sha256 ON issued_certs (sha256);

-- Named counters. 'serial' holds the last certificate serial handed out;
-- it starts at 1 so the first one is 2 (1 is conventionally the CA's).
CREATE TABLE counters (
    name  TEXT PRIMARY KEY,
    value INTEGER NOT NULL
);
INSERT INTO counters (name, value) VALUES ('serial', 1);

CREATE TABLE blobs (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
);

CREATE TABLE events (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    at      TEXT NOT NULL,
    actor   TEXT NOT NULL DEFAULT '',
    kind    TEXT NOT NULL DEFAULT '',
    subject TEXT NOT NULL DEFAULT '',
    detail  TEXT NOT NULL DEFAULT ''
);
