// Drives the Rust server's plugins with the official better-auth JS client plugins.
import { createAuthClient } from "better-auth/client";
import { anonymousClient, adminClient, multiSessionClient, oneTimeTokenClient, deviceAuthorizationClient, phoneNumberClient, emailOTPClient, jwtClient, magicLinkClient, organizationClient, twoFactorClient, usernameClient } from "better-auth/client/plugins";
import { base32 } from "@better-auth/utils/base32";
import { createOTP } from "@better-auth/utils/otp";
import { createLocalJWKSet, jwtVerify } from "jose";
import { apiKeyClient } from "@better-auth/api-key/client";
import { passkeyClient } from "@better-auth/passkey/client";
import { installSoftwareAuthenticator } from "./software-authenticator.mjs";

const baseURL = process.env.BASE_URL ?? "http://localhost:3123";
let failures = 0;
const check = (name, cond, extra) => {
  console.log(`${cond ? "PASS" : "FAIL"} ${name}`);
  if (!cond) { failures++; if (extra !== undefined) console.log("   ", JSON.stringify(extra)); }
};
const lastEmail = async (to, kind) => {
  const all = await (await fetch(`${baseURL}/api/dev/outbox`)).json();
  return all.filter((e) => e.to === to && (!kind || e.kind === kind)).at(-1);
};
const unique = (prefix) => `${prefix}${Date.now()}${Math.floor(Math.random() * 1e6)}@example.com`;

/** A client with its own cookie jar. */
function makeClient(plugins = [], extra = {}) {
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
  const client = createAuthClient({ baseURL, plugins, fetchOptions: { customFetchImpl: fetchWithJar, ...extra } });
  return { client, jar };
}

// ---- bearer -------------------------------------------------------------------------
{
  let token = "";
  const { client } = makeClient([], {
    onSuccess: (ctx) => {
      const t = ctx.response.headers.get("set-auth-token");
      if (t) token = t;
    },
  });
  const email = unique("bearer");
  await client.signUp.email({ email, password: "password1234", name: "Bearer" });
  check("bearer: set-auth-token exposed", token.includes("."), token);
  // A cookie-less client authenticating with the token only.
  const bare = createAuthClient({ baseURL, fetchOptions: { auth: { type: "Bearer", token: () => token } } });
  const s = await bare.getSession();
  check("bearer: getSession with Authorization header", s.data?.user?.email === email, s);
}

// ---- username -----------------------------------------------------------------------
{
  const { client, jar } = makeClient([usernameClient()]);
  const name = `User_${Date.now()}`;
  const up = await client.signUp.email({ email: unique("username"), password: "password1234", name: "U", username: name });
  check("username: sign-up with username", up.data?.user?.username === name.toLowerCase(), up);
  check("username: displayUsername", up.data?.user?.displayUsername === name, up.data?.user);
  const avail = await client.isUsernameAvailable({ username: name });
  check("username: isUsernameAvailable (taken)", avail.data?.available === false, avail);
  jar.clear();
  const signIn = await client.signIn.username({ username: name, password: "password1234" });
  check("username: signIn.username", typeof signIn.data?.token === "string" && signIn.data?.user?.username === name.toLowerCase(), signIn);
  const s = await client.getSession();
  check("username: session after sign-in", s.data?.user?.username === name.toLowerCase(), s);
  const bad = await client.signIn.username({ username: name, password: "wrong-password" });
  check("username: wrong password error", bad.error?.status === 401 && bad.error?.code === "INVALID_USERNAME_OR_PASSWORD", bad.error);
}

// ---- jwt ----------------------------------------------------------------------------
{
  let headerJwt = "";
  const { client } = makeClient([jwtClient()], {
    onSuccess: (ctx) => {
      const t = ctx.response.headers.get("set-auth-jwt");
      if (t) headerJwt = t;
    },
  });
  const email = unique("jwt");
  const up = await client.signUp.email({ email, password: "password1234", name: "J" });
  const { data: tokenData } = await client.token();
  const { data: jwks } = await client.jwks();
  check("jwt: jwks endpoint", Array.isArray(jwks?.keys) && jwks.keys[0]?.alg === "EdDSA", jwks);
  try {
    const { payload } = await jwtVerify(tokenData.token, createLocalJWKSet(jwks), { issuer: baseURL, audience: baseURL });
    check("jwt: token verifies with jose", payload.sub === up.data?.user?.id && payload.email === email, payload);
  } catch (e) {
    check("jwt: token verifies with jose", false, e.message);
  }
  await client.getSession();
  check("jwt: set-auth-jwt on getSession", headerJwt.split(".").length === 3, headerJwt);
}

// ---- magic-link -------------------------------------------------------------------------
{
  const { client } = makeClient([magicLinkClient()]);
  const email = unique("magic");
  const res = await client.signIn.magicLink({ email, name: "Magic", callbackURL: "/dashboard" });
  check("magic-link: signIn.magicLink", res.data?.status === true, res);
  const sent = await lastEmail(email, "magic-link");
  check("magic-link: link emailed", sent?.url?.includes("/magic-link/verify?token="), sent);
  const verified = await client.magicLink.verify({ query: { token: sent.token } });
  check("magic-link: magicLink.verify signs in", verified.data?.user?.email === email && verified.data?.user?.emailVerified === true, verified);
  const s = await client.getSession();
  check("magic-link: session", s.data?.user?.name === "Magic", s);
  const again = await client.magicLink.verify({ query: { token: sent.token, callbackURL: "/dashboard" } });
  check("magic-link: token is single use", again.error?.status === 302 || again.response?.status === 302 || again.data === null, again);
}

// ---- email-otp --------------------------------------------------------------------------
{
  const { client } = makeClient([emailOTPClient()]);
  const email = unique("otp");
  const sent = await client.emailOtp.sendVerificationOtp({ email, type: "sign-in" });
  check("email-otp: sendVerificationOtp", sent.data?.success === true, sent);
  const { token: otp } = await lastEmail(email, "otp");
  const bad = await client.signIn.emailOtp({ email, otp: "000000" === otp ? "111111" : "000000" });
  check("email-otp: wrong code rejected", bad.error?.code === "INVALID_OTP", bad.error);
  const ok = await client.signIn.emailOtp({ email, otp });
  check("email-otp: signIn.emailOtp", ok.data?.user?.email === email && typeof ok.data?.token === "string", ok);
  const s = await client.getSession();
  check("email-otp: session", s.data?.user?.emailVerified === true, s);
}

// ---- two-factor --------------------------------------------------------------------------
{
  let redirected = false;
  const { client, jar } = makeClient([twoFactorClient({ onTwoFactorRedirect: () => { redirected = true; } })]);
  const email = unique("twofa");
  await client.signUp.email({ email, password: "password1234", name: "2FA" });
  const enabled = await client.twoFactor.enable({ password: "password1234" });
  check("two-factor: enable returns totpURI", enabled.data?.totpURI?.startsWith("otpauth://totp/"), enabled);
  const secret = new TextDecoder().decode(base32.decode(new URL(enabled.data.totpURI).searchParams.get("secret")));
  const code = () => createOTP(secret).totp();
  const v1 = await client.twoFactor.verifyTotp({ code: await code() });
  check("two-factor: verifyTotp enrolls (JS-generated code)", v1.data?.token !== undefined, v1);
  await client.signOut();
  jar.clear();
  const signIn = await client.signIn.email({ email, password: "password1234" });
  check("two-factor: sign-in redirects to second factor", redirected && signIn.data?.twoFactorRedirect === true, signIn);
  const pending = await client.getSession();
  check("two-factor: no session before verification", pending.data === null, pending);
  const v2 = await client.twoFactor.verifyTotp({ code: await code(), trustDevice: true });
  check("two-factor: verifyTotp signs in", typeof v2.data?.token === "string", v2);
  const s = await client.getSession();
  check("two-factor: session", s.data?.user?.twoFactorEnabled === true, s);
}

// ---- admin --------------------------------------------------------------------------------
{
  const { client } = makeClient([adminClient()]);
  const adminEmail = unique("admin");
  await client.signUp.email({ email: adminEmail, password: "password1234", name: "Admin" });
  const denied = await client.admin.listUsers({ query: { limit: 5 } });
  check("admin: regular users are denied", denied.error?.status === 403, denied.error);
  await fetch(`${baseURL}/api/dev/make-admin`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email: adminEmail }) });
  const created = await client.admin.createUser({ email: unique("managed"), password: "password1234", name: "Managed", role: "user" });
  check("admin: createUser", created.data?.user?.role === "user", created);
  const list = await client.admin.listUsers({ query: { searchValue: "managed", searchField: "email", searchOperator: "starts_with" } });
  check("admin: listUsers", list.data?.users?.length >= 1 && typeof list.data?.total === "number", list);
  const banned = await client.admin.banUser({ userId: created.data.user.id, banReason: "e2e" });
  check("admin: banUser", banned.data?.user?.banned === true, banned);
  const perm = await client.admin.hasPermission({ permissions: { user: ["ban"] } });
  check("admin: hasPermission", perm.data?.success === true, perm);
  const imp = await client.admin.impersonateUser({ userId: (await client.admin.createUser({ email: unique("target"), password: "password1234", name: "T" })).data.user.id });
  check("admin: impersonateUser", typeof imp.data?.session?.impersonatedBy === "string", imp);
  const stop = await client.admin.stopImpersonating();
  check("admin: stopImpersonating", stop.data?.user?.email === adminEmail, stop);
}

// ---- organization ---------------------------------------------------------------------------
{
  const { client: owner } = makeClient([organizationClient({ teams: { enabled: true } })]);
  const { client: invitee } = makeClient([organizationClient({ teams: { enabled: true } })]);
  const ownerEmail = unique("orgowner");
  const inviteeEmail = unique("invitee");
  await owner.signUp.email({ email: ownerEmail, password: "password1234", name: "Owner" });
  await invitee.signUp.email({ email: inviteeEmail, password: "password1234", name: "Invitee" });
  const slug = `org-${Date.now()}`;
  const org = await owner.organization.create({ name: "E2E Org", slug, metadata: { plan: "pro" } });
  check("organization: create", org.data?.slug === slug && org.data?.members?.[0]?.role === "owner", org);
  const slugCheck = await owner.organization.checkSlug({ slug });
  check("organization: checkSlug taken", slugCheck.error?.code === "ORGANIZATION_SLUG_ALREADY_TAKEN", slugCheck);
  const team = await owner.organization.createTeam({ name: "Core" });
  check("organization: createTeam", team.data?.name === "Core", team);
  const inv = await owner.organization.inviteMember({ email: inviteeEmail, role: "admin", teamId: team.data.id });
  check("organization: inviteMember", inv.data?.status === "pending", inv);
  const sent = await lastEmail(inviteeEmail, "invitation");
  check("organization: invitation email", sent?.token === inv.data.id, sent);
  const acc = await invitee.organization.acceptInvitation({ invitationId: inv.data.id });
  check("organization: acceptInvitation", acc.data?.member?.role === "admin", acc);
  const full = await owner.organization.getFullOrganization();
  check("organization: getFullOrganization", full.data?.members?.length === 2 && full.data?.teams?.length === 2, full);
  const members = await owner.organization.listMembers();
  check("organization: listMembers", members.data?.total === 2, members);
  const active = await invitee.organization.getActiveMember();
  check("organization: getActiveMember", active.data?.role === "admin", active);
  const perm = await invitee.organization.hasPermission({ permissions: { member: ["delete"] } });
  check("organization: hasPermission", perm.data?.success === true, perm);
  const teamMembers = await invitee.organization.listTeamMembers({ query: { teamId: team.data.id } });
  check("organization: listTeamMembers", teamMembers.data?.length === 1, teamMembers);
  const list = await owner.organization.list();
  check("organization: list", list.data?.length === 1, list);
}

// ---- anonymous ------------------------------------------------------------------------------
{
  const { client } = makeClient([anonymousClient()]);
  const anon = await client.signIn.anonymous();
  check("anonymous: signIn.anonymous", anon.data?.user?.isAnonymous === true, anon);
  const email = unique("linked");
  await client.signUp.email({ email, password: "password1234", name: "Linked" });
  const s = await client.getSession();
  check("anonymous: linking to a real account", s.data?.user?.email === email && s.data?.user?.isAnonymous === false, s);
}

// ---- multi-session --------------------------------------------------------------------------
{
  const { client } = makeClient([multiSessionClient()]);
  const a = unique("multi-a"), b = unique("multi-b");
  await client.signUp.email({ email: a, password: "password1234", name: "A" });
  await client.signUp.email({ email: b, password: "password1234", name: "B" });
  const list = await client.multiSession.listDeviceSessions();
  check("multi-session: listDeviceSessions", list.data?.length === 2, list);
  const first = list.data?.find((s) => s.user.email === a);
  const active = await client.multiSession.setActive({ sessionToken: first?.session.token });
  check("multi-session: setActive", active.data?.user?.email === a, active);
  const revoked = await client.multiSession.revoke({ sessionToken: first?.session.token });
  const s = await client.getSession();
  check("multi-session: revoke switches session", revoked.data?.status === true && s.data?.user?.email === b, s);
}

// ---- phone-number ---------------------------------------------------------------------------
{
  const { client } = makeClient([phoneNumberClient()]);
  const phoneNumber = `+1${Date.now()}`.slice(0, 13);
  const sent = await client.phoneNumber.sendOtp({ phoneNumber });
  check("phone-number: sendOtp", sent.data?.message === "code sent", sent);
  const code = (await lastEmail(phoneNumber, "sms"))?.token;
  const verified = await client.phoneNumber.verify({ phoneNumber, code });
  check("phone-number: verify signs up", verified.data?.user?.phoneNumberVerified === true && !!verified.data?.token, verified);
  await client.phoneNumber.requestPasswordReset({ phoneNumber });
  const otp = (await lastEmail(phoneNumber, "sms-reset"))?.token;
  const reset = await client.phoneNumber.resetPassword({ phoneNumber, otp, newPassword: "password1234" });
  check("phone-number: resetPassword", reset.data?.status === true, reset);
  await client.signOut();
  const signIn = await client.signIn.phoneNumber({ phoneNumber, password: "password1234" });
  check("phone-number: signIn.phoneNumber", signIn.data?.user?.phoneNumber === phoneNumber, signIn);
}

// ---- one-time-token -------------------------------------------------------------------------
{
  const { client } = makeClient([oneTimeTokenClient()]);
  const email = unique("ott");
  await client.signUp.email({ email, password: "password1234", name: "OTT" });
  const generated = await client.oneTimeToken.generate();
  check("one-time-token: generate", typeof generated.data?.token === "string", generated);
  const { client: other } = makeClient([oneTimeTokenClient()]);
  const verified = await other.oneTimeToken.verify({ token: generated.data?.token });
  check("one-time-token: verify", verified.data?.user?.email === email, verified);
  const s = await other.getSession();
  check("one-time-token: session cookie set", s.data?.user?.email === email, s);
  const again = await other.oneTimeToken.verify({ token: generated.data?.token });
  check("one-time-token: single use", again.error?.status === 400, again);
}

// ---- last-login-method ----------------------------------------------------------------------
{
  const { client, jar } = makeClient([]);
  const email = unique("llm");
  await client.signUp.email({ email, password: "password1234", name: "LLM" });
  check("last-login-method: cookie", jar.get("better-auth.last_used_login_method") === "email", [...jar.keys()]);
  const s = await client.getSession();
  check("last-login-method: stored on user", s.data?.user?.lastLoginMethod === "email", s);
}

// ---- open-api -------------------------------------------------------------------------------
{
  const doc = await (await fetch(`${baseURL}/api/auth/open-api/generate-schema`)).json();
  check("open-api: generate-schema", doc.openapi === "3.1.1" && !!doc.paths?.["/sign-in/email"]?.post, Object.keys(doc));
  const page = await fetch(`${baseURL}/api/auth/reference`);
  const html = await page.text();
  check("open-api: reference page", page.headers.get("content-type") === "text/html" && html.includes("api-reference"), page.status);
}

// ---- device-authorization -------------------------------------------------------------------
{
  const { client: device } = makeClient([deviceAuthorizationClient()]);
  const code = await device.device.code({ client_id: "e2e-tv", scope: "openid" });
  check("device: code", typeof code.data?.device_code === "string" && code.data?.interval === 5, code);
  const pending = await device.device.token({ grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: code.data.device_code, client_id: "e2e-tv" });
  check("device: authorization_pending", pending.error?.error === "authorization_pending", pending);
  const { client: user } = makeClient([deviceAuthorizationClient()]);
  await user.signUp.email({ email: unique("device"), password: "password1234", name: "Device" });
  const review = await user.device({ query: { user_code: code.data.user_code } });
  check("device: verify", review.data?.client_id === "e2e-tv" && review.data?.status === "pending", review);
  const approved = await user.device.approve({ userCode: code.data.user_code });
  check("device: approve", approved.data?.success === true, approved);
}

// ---- api-key -------------------------------------------------------------------------
{
  const { client } = makeClient([apiKeyClient()]);
  const email = unique("apikey");
  await client.signUp.email({ email, password: "password1234", name: "Api Key" });
  const created = await client.apiKey.create({ name: "e2e", prefix: "e2e_", metadata: { env: "test" } });
  check("api-key: create", created.data?.key?.startsWith("e2e_") && created.data?.metadata?.env === "test", created);
  const got = await client.apiKey.get({ query: { id: created.data?.id } });
  check("api-key: get", got.data?.name === "e2e" && got.data?.key === undefined && got.data?.metadata?.env === "test", got);
  const listed = await client.apiKey.list();
  check("api-key: list", listed.data?.total === 1 && listed.data?.apiKeys?.[0]?.id === created.data?.id, listed);
  const updated = await client.apiKey.update({ keyId: created.data?.id, name: "renamed" });
  check("api-key: update", updated.data?.name === "renamed", updated);
  const serverOnly = await client.apiKey.create({ remaining: 5 });
  check("api-key: server-only property rejected", serverOnly.error?.code === "SERVER_ONLY_PROPERTY", serverOnly);
  // The key alone authenticates.
  const res = await fetch(`${baseURL}/api/auth/get-session`, { headers: { "x-api-key": created.data?.key } });
  const s = await res.json();
  check("api-key: session from x-api-key", s?.user?.email === email, s);
  const deleted = await client.apiKey.delete({ keyId: created.data?.id });
  check("api-key: delete", deleted.data?.success === true, deleted);
  const gone = await fetch(`${baseURL}/api/auth/get-session`, { headers: { "x-api-key": created.data?.key } });
  await gone.body?.cancel();
  check("api-key: deleted key rejected", gone.status === 401, gone.status);
}

// ---- passkey ---------------------------------------------------------------------------
// The official client drives @simplewebauthn/browser, backed here by a software
// authenticator standing in for navigator.credentials.
{
  const authenticator = installSoftwareAuthenticator(baseURL);
  const { client } = makeClient([passkeyClient()]);
  const email = unique("passkey");
  await client.signUp.email({ email, password: "password1234", name: "Passkey" });
  const added = await client.passkey.addPasskey({ name: "Software key" });
  check("passkey: addPasskey", added.data?.name === "Software key" && added.data?.credentialID === authenticator.credentialId(), added);
  const listed = await client.passkey.listUserPasskeys();
  check("passkey: listUserPasskeys", listed.data?.length === 1 && listed.data[0].deviceType === "multiDevice", listed);
  const { client: fresh } = makeClient([passkeyClient()]);
  const signedIn = await fresh.signIn.passkey();
  check("passkey: signIn.passkey", signedIn.data?.user?.email === email, signedIn);
  const session = await fresh.getSession();
  check("passkey: session after sign-in", session.data?.user?.email === email, session);
  check("passkey: counter advanced", authenticator.counter() === 1);
  const renamed = await client.passkey.updatePasskey({ id: added.data?.id, name: "Renamed" });
  check("passkey: updatePasskey", renamed.data?.passkey?.name === "Renamed", renamed);
  const deleted = await client.passkey.deletePasskey({ id: added.data?.id });
  check("passkey: deletePasskey", deleted.data?.status === true, deleted);
  const again = await makeClient([passkeyClient()]).client.signIn.passkey();
  check("passkey: deleted passkey rejected", again.error?.code === "PASSKEY_NOT_FOUND", again);
}

if (failures) {
  console.log(`\n${failures} failure(s)`);
  process.exit(1);
}
console.log("\nplugins: all passed");
