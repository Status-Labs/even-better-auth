// Verify the JS `getCookieCache` helper reads cookie caches produced by the Rust server.
import { getCookieCache } from "better-auth/cookies";
const baseURL = process.env.BASE_URL, strategy = process.env.STRATEGY, secret = process.env.BETTER_AUTH_SECRET;
const res = await fetch(`${baseURL}/api/auth/sign-up/email`, {
  method: "POST", headers: { "content-type": "application/json", origin: baseURL },
  body: JSON.stringify({ email: `c${Date.now()}@example.com`, password: "password1234", name: "Cache" }),
});
const cookies = res.headers.getSetCookie().map((c) => c.split(";")[0]).join("; ");
const headers = new Headers({ cookie: cookies });
const cache = await getCookieCache(headers, { secret, strategy, isSecure: false });
const ok = cache?.user?.name === "Cache" && typeof cache?.session?.token === "string";
console.log(`${ok ? "PASS" : "FAIL"} getCookieCache strategy=${strategy}`);
if (!ok) { console.log(cookies.slice(0, 300)); process.exit(1); }
