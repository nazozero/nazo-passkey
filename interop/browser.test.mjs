import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { release, version } from "node:os";
import { resolve } from "node:path";
import { createInterface } from "node:readline";
import { after, before, test } from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { decode } from "cborg";
import { chromium } from "playwright";
import playwright from "playwright/package.json" with { type: "json" };

const origin = "http://localhost:3000";
const root = fileURLToPath(new URL("../", import.meta.url));
const examples = resolve(root, process.env.CARGO_TARGET_DIR ?? "target", "debug", "examples");
const suffix = process.platform === "win32" ? ".exe" : "";
const usb = {
  transport: "usb",
  hasResidentKey: false,
  hasUserVerification: false,
  isUserVerified: false,
  defaultBackupEligibility: false,
  defaultBackupState: false,
};
let browser;

before(async () => {
  browser = await chromium.launch({ channel: "chromium" });
});

after(async () => {
  await browser?.close();
});

async function startDemo(t, example, profile) {
  const server = spawn(resolve(examples, example + suffix), {
    cwd: root,
    stdio: ["ignore", "pipe", "inherit"],
  });
  const stopped = new Promise((done) => server.once("close", done));
  const stdout = createInterface({ input: server.stdout });
  let context;
  t.after(async () => {
    try {
      await context?.close();
    } finally {
      server.kill();
      await stopped;
    }
  });

  const [line] = await Promise.race([
    once(stdout, "line", { signal: AbortSignal.timeout(10_000) }),
    once(server, "exit").then(([code]) => {
      throw new Error(`${example} exited before listening (code ${code})`);
    }),
  ]);
  assert.ok(line.endsWith(` listening on ${origin}`), line);
  context = await browser.newContext();
  const page = await context.newPage();
  assert.equal((await page.goto(origin)).status(), 200);
  const cdp = await context.newCDPSession(page);
  const options = {
    protocol: "ctap2",
    ctap2Version: "ctap2_1",
    automaticPresenceSimulation: true,
    ...profile,
  };
  const { product, revision, protocolVersion } = await cdp.send("Browser.getVersion");
  t.diagnostic(JSON.stringify({
    example, origin,
    browser: { product, revision, protocolVersion },
    os: { platform: process.platform, arch: process.arch, version: version(), release: release() },
    node: process.version,
    playwright: playwright.version,
    authenticator: options,
  }));
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", { options });
  return { page, cdp, authenticatorId };
}

async function request(page, path, { body, method = "POST", status = 200 } = {}) {
  const response = await page.evaluate(async ({ path, method, body }) => {
    const result = await fetch(path, {
      method,
      headers: body === undefined ? undefined : { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(10_000),
    });
    return { status: result.status, text: await result.text() };
  }, { path, method, body });
  assert.equal(response.status, status, `${method} ${path}: ${response.text}`);
  return status === 200 ? JSON.parse(response.text) : response.text;
}

async function getCredentialJSON(page, operation, options) {
  const credential = await page.evaluate(async ({ operation, options }) => {
    const parse = operation === "create"
      ? PublicKeyCredential.parseCreationOptionsFromJSON
      : PublicKeyCredential.parseRequestOptionsFromJSON;
    const credential = await navigator.credentials[operation]({
      publicKey: parse.call(PublicKeyCredential, options),
      signal: AbortSignal.timeout(12_000),
    });
    return credential.toJSON();
  }, { operation, options });
  assert.equal(credential.type, "public-key");
  assert.equal(credential.id, credential.rawId);
  return credential;
}

function authenticatorData(bytes) {
  assert.ok(bytes.length >= 37);
  const flags = bytes[32];
  assert.ok(flags & 0x01, "expected user presence");
  return {
    uv: Boolean(flags & 0x04),
    be: Boolean(flags & 0x08),
    bs: Boolean(flags & 0x10),
    counter: bytes.readUInt32BE(33),
  };
}

async function register(page, uv, username) {
  const options = await request(page, "/register/start", {
    body: username === undefined ? undefined : { username },
  });
  assert.equal(options.authenticatorSelection.userVerification, uv);
  assert.equal(options.attestation, "none");
  if (username !== undefined) {
    // Match the passwordless demo's resident-key requirement.
    options.authenticatorSelection.residentKey = "required";
    options.authenticatorSelection.requireResidentKey = true;
  }
  const body = await getCredentialJSON(page, "create", options);
  const { attestationObject } = body.response;
  const attestation = decode(Buffer.from(attestationObject, "base64url"));
  assert.equal(attestation.fmt, "none");
  assert.deepEqual(attestation.attStmt, {});
  const data = authenticatorData(Buffer.from(attestation.authData));
  const result = await request(page, "/register/finish", { body });
  assert.equal(result.ok, true);
  return { id: body.id, userHandle: options.user.id, data, result };
}

async function assertion(page, uv, allow) {
  const options = await request(page, "/authenticate/start");
  assert.equal(options.userVerification, uv);
  assert.deepEqual((options.allowCredentials ?? []).map(({ id }) => id), allow);
  const body = await getCredentialJSON(page, "get", options);
  return {
    body,
    data: authenticatorData(Buffer.from(body.response.authenticatorData, "base64url")),
  };
}

async function rejectsAssertion(page, body, expected) {
  assert.match(await request(page, "/authenticate/finish", { body, status: 401 }), expected);
}

test("username-first with preferred UV and a non-discoverable USB credential", { timeout: 90_000 }, async (t) => {
  const { page, cdp, authenticatorId } = await startDemo(t, "axum_server", usb);
  const registration = await register(page, "preferred");
  assert.equal(registration.result.credential_id, registration.id);
  assert.partialDeepStrictEqual(registration.data, { uv: false, be: false, bs: false });

  const counters = [];
  let previous = registration.data.counter;
  for (let i = 0; i < 2; i++) {
    const { body, data } = await assertion(page, "preferred", [registration.id]);
    assert.equal(body.id, registration.id);
    assert.equal(body.response.userHandle ?? null, null);
    assert.ok(data.counter > previous);
    assert.partialDeepStrictEqual(data, { uv: false, be: false, bs: false });
    assert.deepEqual(await request(page, "/authenticate/finish", { body }), {
      ok: true, user_verified: false, new_counter: data.counter,
    });
    counters.push(data.counter);
    previous = data.counter;
  }

  // Use the same virtual credential to sign a fresh challenge with a repeated counter.
  await cdp.send("WebAuthn.setCredentialProperties", {
    authenticatorId,
    credentialId: Buffer.from(registration.id, "base64url").toString("base64"),
    signCount: previous - 1,
  });
  const repeated = await assertion(page, "preferred", [registration.id]);
  assert.equal(repeated.data.counter, previous);
  await rejectsAssertion(page, repeated.body, /counter went backwards/);

  const allow = [registration.id];
  const wrongAccount = await assertion(page, "preferred", allow);
  wrongAccount.body.response.userHandle = Buffer.from("another account").toString("base64url");
  await rejectsAssertion(page, wrongAccount.body, /user handle mismatch/);

  const wrongRp = await assertion(page, "preferred", allow);
  const authData = Buffer.from(wrongRp.body.response.authenticatorData, "base64url");
  authData[0] ^= 1; // First byte of the RP ID hash in authenticator data.
  wrongRp.body.response.authenticatorData = authData.toString("base64url");
  await rejectsAssertion(page, wrongRp.body, /rpIdHash mismatch/);

  const wrongSignature = await assertion(page, "preferred", allow);
  wrongSignature.body.response.signature = repeated.body.response.signature;
  await rejectsAssertion(page, wrongSignature.body, /signature verification failed/);

  // Change only the browser origin's port. Its RP ID and virtual credential
  // stay the same, so Chromium can produce a genuine assertion for this origin.
  const options = await request(page, "/authenticate/start");
  const alternateOrigin = "http://localhost:3001/";
  await page.route(alternateOrigin, (route) => route.fulfill({ contentType: "text/html", body: "<!doctype html>" }));
  await page.goto(alternateOrigin);
  const wrongOrigin = await getCredentialJSON(page, "get", options);
  await page.goto(origin);
  await rejectsAssertion(page, wrongOrigin, /origin mismatch/);

  t.diagnostic(JSON.stringify({ attestation: "none", registration: registration.data, counters, repeatedCounter: previous }));
});

test("discoverable sign-in with required UV and backup flags", { timeout: 90_000 }, async (t) => {
  const { page, cdp, authenticatorId } = await startDemo(t, "axum_passwordless", {
    transport: "internal",
    hasResidentKey: true,
    hasUserVerification: true,
    isUserVerified: true,
    defaultBackupEligibility: true,
    defaultBackupState: false,
  });
  const username = "interop@example.test";
  const registration = await register(page, "required", username);
  assert.equal(registration.result.username, username);
  assert.partialDeepStrictEqual(registration.data, { uv: true, be: true, bs: false });

  const stale = await assertion(page, "required", []);
  await request(page, "/authenticate/start");
  await rejectsAssertion(page, stale.body, /challenge mismatch/);
  assert.match(await request(page, "/authenticate/finish", { body: stale.body, status: 400 }),
    /no authentication in flight/);
  await request(page, "/whoami", { method: "GET", status: 401 });

  await cdp.send("WebAuthn.setResponseOverrideBits", { authenticatorId, isBadUV: true });
  const noUv = await assertion(page, "required", []);
  assert.equal(noUv.data.uv, false);
  await rejectsAssertion(page, noUv.body, /user-verified flag not set/);
  await cdp.send("WebAuthn.setResponseOverrideBits", { authenticatorId });

  await cdp.send("WebAuthn.setCredentialProperties", {
    authenticatorId,
    credentialId: Buffer.from(registration.id, "base64url").toString("base64"),
    backupState: true,
  });
  const { body, data } = await assertion(page, "required", []);
  assert.equal(body.id, registration.id);
  assert.equal(body.response.userHandle, registration.userHandle);
  assert.ok(data.counter > stale.data.counter);
  assert.partialDeepStrictEqual(data, { uv: true, be: true, bs: true });
  assert.deepEqual(await request(page, "/authenticate/finish", { body }), {
    ok: true, user_verified: true, username,
  });
  assert.deepEqual(await request(page, "/whoami", { method: "GET" }), { username });
  t.diagnostic(JSON.stringify({ attestation: "none", registration: registration.data, signedIn: data }));
});

test("browser assertion is rejected after the server's five-minute state expiry", { timeout: 360_000 }, async (t) => {
  const { page } = await startDemo(t, "axum_server", usb);
  const { id } = await register(page, "preferred");
  const { body } = await assertion(page, "preferred", [id]);
  // Wait out the actual server TTL. Keep the browser response byte-for-byte intact.
  await delay(302_000, undefined, { signal: t.signal });
  await rejectsAssertion(page, body, /ceremony state expired/);
});
