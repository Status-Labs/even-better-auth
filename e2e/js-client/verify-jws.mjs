// Verifies Rust-signed JWS tokens with jose: JWS_OUT=out.json cargo test -p even-better-auth --test js_compat -- --ignored write_rust_jws_vectors && node verify-jws.mjs out.json
import { readFileSync } from "node:fs";
import { importJWK, jwtVerify } from "jose";
const vectors = JSON.parse(readFileSync(process.argv[2], "utf8"));
let failed = false;
for (const [alg, { jwk, token }] of Object.entries(vectors)) {
  try {
    const { payload } = await jwtVerify(token, await importJWK(jwk, alg), { algorithms: [alg] });
    console.log(payload.sub === "rust" ? "PASS" : "FAIL", alg);
  } catch (e) {
    failed = true;
    console.log("FAIL", alg, e.message);
  }
}
process.exit(failed ? 1 : 0);
