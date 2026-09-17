import { openDb } from "./db.js";
import { loadOrCreateServerKeys } from "./keys.js";
import { loadOrCreateTotpEncryptionKey } from "./totpCrypto.js";
import { createApp } from "./app.js";

const dbPath = process.env.CLA_DB_PATH ?? ".data/cla.sqlite";
const keyPath = process.env.CLA_SERVER_KEY_PATH ?? ".data/server-key.json";
const totpKeyPath = process.env.CLA_TOTP_KEY_PATH ?? ".data/totp-key.json";
const port = Number(process.env.PORT ?? 8787);

const db = openDb(dbPath);
const { keyId, privateKey } = loadOrCreateServerKeys(keyPath);
const totpEncryptionKey = loadOrCreateTotpEncryptionKey(totpKeyPath);

const app = createApp(db, privateKey, keyId, totpEncryptionKey);
app.listen(port, () => {
  console.log(`CLA reference server listening on http://localhost:${port}`);
  console.log(`Server key id: ${keyId}`);
});
