export interface RpConfig {
  rpName: string;
  rpID: string;
  origin: string;
}

export function loadRpConfig(): RpConfig {
  return {
    rpName: process.env.CLA_RP_NAME ?? "CLA Demo",
    rpID: process.env.CLA_RP_ID ?? "localhost",
    origin: process.env.CLA_ORIGIN ?? "http://localhost:5173",
  };
}

export function bufferToBase64(buf: Uint8Array): string {
  return Buffer.from(buf).toString("base64");
}

export function base64ToUint8Array(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, "base64"));
}
