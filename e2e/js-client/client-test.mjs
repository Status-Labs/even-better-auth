// Drives the Rust server with the official better-auth JS client.
import { createAuthClient } from "better-auth/client";

const baseURL = process.env.BASE_URL ?? "http://localhost:3123";
const jar = new Map();
const fetchWithJar = async (input, init = {}) => {
  const headers = new Headers(init.headers);
  if (jar.size) headers.set("cookie", [...jar].map(([k, v]) => `${k}=${v}`).join("; "));
  headers.set("origin", baseURL);
  const res = await fetch(input, { ...init, headers, redirect: "manual" });
  for (const c of res.headers.getSetCookie()) {
    const [pair] = c.split(";");
    const i = pair.indexOf("=");
    const name = pair.slice(0, i), value = pair.slice(i + 1);
    if (!value || /max-age=0/i.test(c)) jar.delete(name); else jar.set(name, value);
  }
  return res;
};
const client = createAuthClient({ baseURL, fetchOptions: { customFetchImpl: fetchWithJar } });

let failures = 0;
const check = (name, cond, extra) => {
  console.log(`${cond ? "PASS" : "FAIL"} ${name}`);
  if (!cond) { failures++; if (extra !== undefined) console.log("   ", JSON.stringify(extra)); }
};

const email = `user${Date.now()}@example.com`;
const up = await client.signUp.email({ email, password: "password1234", name: "JS Client" });
check("signUp.email", up.data?.user?.email === email && typeof up.data?.token === "string", up);
check("session cookie set", jar.has("better-auth.session_token"));

const s1 = await client.getSession();
check("getSession after sign-up", s1.data?.user?.email === email && s1.data?.session?.userId === up.data?.user?.id, s1);
check("dates parse", !Number.isNaN(new Date(s1.data?.session?.expiresAt).getTime()));

const dup = await client.signUp.email({ email, password: "password1234", name: "x" });
check("duplicate sign-up error", dup.error?.status === 422 && dup.error?.code === "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL", dup.error);

const out = await client.signOut();
check("signOut", out.data?.success === true, out);
const s2 = await client.getSession();
check("getSession after sign-out is null", s2.data === null, s2);

const bad = await client.signIn.email({ email, password: "wrong-password" });
check("signIn wrong password", bad.error?.status === 401 && bad.error?.code === "INVALID_EMAIL_OR_PASSWORD", bad.error);

const inn = await client.signIn.email({ email, password: "password1234", rememberMe: false });
check("signIn.email", inn.data?.user?.email === email && inn.data?.redirect === false, inn);
check("dont_remember cookie", jar.has("better-auth.dont_remember"));

const ls = await client.listSessions();
check("listSessions", Array.isArray(ls.data) && ls.data.length === 1, ls);

const upd = await client.updateUser({ name: "Renamed" });
check("updateUser", upd.data?.status === true, upd);
const s3 = await client.getSession();
check("updated name visible", s3.data?.user?.name === "Renamed", s3);

const cp = await client.changePassword({ currentPassword: "password1234", newPassword: "newpassword5678", revokeOtherSessions: true });
check("changePassword", typeof cp.data?.token === "string" && cp.data?.user?.email === email, cp);
await client.signOut();
const inn2 = await client.signIn.email({ email, password: "newpassword5678" });
check("signIn with new password", inn2.data?.user?.email === email, inn2);

const rpr = await client.requestPasswordReset({ email, redirectTo: "/reset" });
check("requestPasswordReset", rpr.data?.status === true, rpr);

const social = await client.signIn.social({ provider: "github", callbackURL: "/dashboard", disableRedirect: true });
const authURL = social.data?.url ? new URL(social.data.url) : null;
check("signIn.social returns provider URL",
  authURL?.origin === "https://github.com" && authURL.searchParams.get("client_id") === "e2e-client-id" &&
  authURL.searchParams.get("code_challenge_method") === "S256" &&
  authURL.searchParams.get("redirect_uri") === `${baseURL}/api/auth/callback/github` && social.data?.redirect === false, social);
check("state cookie set", jar.has("better-auth.state"));
const cb = await fetchWithJar(`${baseURL}/api/auth/callback/github?state=bogus&code=x`);
check("callback with bad state redirects to error", cb.status === 302 && /error=/.test(cb.headers.get("location") ?? ""), cb.headers.get("location"));

const ok = await fetchWithJar(`${baseURL}/api/auth/ok`).then((r) => r.json());
check("/ok", ok.ok === true, ok);

console.log(failures ? `\n${failures} failure(s)` : "\nall passed");
process.exit(failures ? 1 : 0);
