// A software WebAuthn authenticator installed as navigator.credentials, so the official
// browser-side code (@simplewebauthn/browser via @better-auth/passkey/client) runs in Node.
// One ES256 credential; "none" attestation; backup-eligible and backed up.
import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";

const b64url = (buf) => Buffer.from(buf).toString("base64url");
const sha256 = (data) => createHash("sha256").update(data).digest();
const toArrayBuffer = (buf) => buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);

// Minimal CBOR: unsigned/negative ints, byte strings, text strings, maps.
function head(major, n) {
  if (n < 24) return Buffer.from([(major << 5) | n]);
  if (n < 0x100) return Buffer.from([(major << 5) | 24, n]);
  const b = Buffer.alloc(3);
  b[0] = (major << 5) | 25;
  b.writeUInt16BE(n, 1);
  return b;
}
function cbor(value) {
  if (typeof value === "number") return value >= 0 ? head(0, value) : head(1, -1 - value);
  if (typeof value === "string") return Buffer.concat([head(3, Buffer.byteLength(value)), Buffer.from(value)]);
  if (Buffer.isBuffer(value)) return Buffer.concat([head(2, value.length), value]);
  if (value instanceof Map) return Buffer.concat([head(5, value.size), ...[...value].flatMap(([k, v]) => [cbor(k), cbor(v)])]);
  throw new Error(`cannot encode ${value}`);
}

export function installSoftwareAuthenticator(origin) {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" });
  const credentialId = randomBytes(16);
  let counter = 0;
  const flags = 0x01 | 0x04 | 0x08 | 0x10; // UP, UV, BE, BS
  const clientData = (type, challenge) =>
    Buffer.from(JSON.stringify({ type, challenge: b64url(challenge), origin, crossOrigin: false }));

  const credentials = {
    async create({ publicKey: options }) {
      const cdj = clientData("webauthn.create", options.challenge);
      const cose = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, "base64url")], [-3, Buffer.from(jwk.y, "base64url")]]));
      const idLen = Buffer.alloc(2);
      idLen.writeUInt16BE(credentialId.length);
      const authData = Buffer.concat([sha256(options.rp.id), Buffer.from([flags | 0x40]), Buffer.alloc(4), Buffer.alloc(16), idLen, credentialId, cose]);
      const attestation = cbor(new Map([["fmt", "none"], ["attStmt", new Map()], ["authData", authData]]));
      return {
        id: b64url(credentialId),
        rawId: toArrayBuffer(credentialId),
        type: "public-key",
        authenticatorAttachment: "platform",
        response: { clientDataJSON: toArrayBuffer(cdj), attestationObject: toArrayBuffer(attestation), getTransports: () => ["internal"] },
        getClientExtensionResults: () => ({}),
      };
    },
    async get({ publicKey: options }) {
      counter += 1;
      const cdj = clientData("webauthn.get", options.challenge);
      const count = Buffer.alloc(4);
      count.writeUInt32BE(counter);
      const authData = Buffer.concat([sha256(options.rpId), Buffer.from([flags]), count]);
      const signature = sign("sha256", Buffer.concat([authData, sha256(cdj)]), privateKey); // DER
      return {
        id: b64url(credentialId),
        rawId: toArrayBuffer(credentialId),
        type: "public-key",
        authenticatorAttachment: "platform",
        response: { clientDataJSON: toArrayBuffer(cdj), authenticatorData: toArrayBuffer(authData), signature: toArrayBuffer(signature), userHandle: null },
        getClientExtensionResults: () => ({}),
      };
    },
  };
  globalThis.PublicKeyCredential ??= class PublicKeyCredential {};
  Object.defineProperty(globalThis.navigator, "credentials", { value: credentials, configurable: true });
  return { credentialId: () => b64url(credentialId), counter: () => counter };
}
