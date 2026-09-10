const test = require("node:test");
const assert = require("node:assert");

const { createAuthBoundry } = require("./authboundry.js");

function stubFetch(routes) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, init });
    const path = url.replace(/^https?:\/\/[^/]+/, "");
    const route = routes[`${(init && init.method) || "GET"} ${path}`];
    if (!route) {
      return { ok: false, status: 404, text: async () => JSON.stringify({ error: "not_found" }) };
    }
    return {
      ok: route.status < 400,
      status: route.status,
      text: async () => JSON.stringify(route.body),
    };
  };
  return { fetchImpl, calls };
}

const ALICE = {
  authenticated: true,
  principal: { id: "prn_alice", kind: "human" },
  tenant: { id: "acme" },
  claims: { role: "owner" },
  capabilities: ["invoice.read", "invoice.create"],
  session: { expires_at: 4600 },
  delegation: null,
};

test("session() reflects what the server says", async () => {
  const { fetchImpl } = stubFetch({ "GET /auth/session": { status: 200, body: ALICE } });
  const auth = createAuthBoundry({ fetch: fetchImpl });

  const context = await auth.session();

  assert.equal(context.principal.id, "prn_alice");
  assert.deepEqual(auth.auth.capabilities, ["invoice.read", "invoice.create"]);
});

test("an unauthenticated browser holds no authority", async () => {
  const { fetchImpl } = stubFetch({
    "GET /auth/session": { status: 401, body: { error: "unauthenticated" } },
  });
  const auth = createAuthBoundry({ fetch: fetchImpl });

  const context = await auth.session();

  assert.equal(context.authenticated, false);
  assert.deepEqual(context.capabilities, []);
  assert.equal(auth.can("invoice.read"), false);
});

test("client state is a projection: the server still decides", async () => {
  const { fetchImpl, calls } = stubFetch({
    "GET /auth/session": { status: 200, body: ALICE },
    // The server refuses billing.charge no matter what the page believes.
    "POST /auth/authorize": { status: 200, body: { allowed: false, reason: "capability_not_granted" } },
  });
  const auth = createAuthBoundry({ fetch: fetchImpl });
  await auth.session();

  // A page can lie to itself...
  auth.auth.capabilities.push("billing.charge");
  assert.equal(auth.can("billing.charge"), true);

  // ... and gains nothing by it.
  assert.equal(await auth.authorize("billing.charge"), false);
  const authorizeCall = calls.find((call) => call.url.endsWith("/auth/authorize"));
  assert.equal(JSON.parse(authorizeCall.init.body).capability, "billing.charge");
});

test("sign-in failures leave the client anonymous", async () => {
  const { fetchImpl } = stubFetch({
    "POST /auth/sign-in": { status: 401, body: { reason: "invalid_credentials", message: "no" } },
  });
  const auth = createAuthBoundry({ fetch: fetchImpl });

  await assert.rejects(() => auth.signIn({ tenant: "acme", connector: "local" }), /no/);
  assert.equal(auth.auth.authenticated, false);
});

test("sign-in applies configured bridge defaults without overriding supplied credentials", async () => {
  let submitted;
  const client = createAuthBoundry({
    tenant: "development",
    connector: "local",
    fetch: async (_url, init) => {
      submitted = JSON.parse(init.body);
      return { ok: false, status: 401, text: async () => '{"reason":"unknown_principal"}' };
    },
  });
  await assert.rejects(() => client.signIn({ username: "admin", password: "secret" }));
  assert.deepEqual(submitted, {
    tenant: "development",
    connector: "local",
    username: "admin",
    password: "secret",
  });
});

test("subscribers see every authority change", async () => {
  const { fetchImpl } = stubFetch({
    "GET /auth/session": { status: 200, body: ALICE },
    "POST /auth/sign-out": { status: 200, body: {} },
  });
  const auth = createAuthBoundry({ fetch: fetchImpl });
  const seen = [];
  auth.subscribe((state) => seen.push(state.auth.authenticated));

  await auth.session();
  await auth.signOut();

  assert.deepEqual(seen, [false, true, false]);
});
