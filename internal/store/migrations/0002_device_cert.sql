-- The certificate (hex SHA-256 of its DER) a device presented when it
-- enrolled, so that removing the device can revoke it.
ALTER TABLE devices ADD COLUMN cert_sha256 TEXT NOT NULL DEFAULT '';
