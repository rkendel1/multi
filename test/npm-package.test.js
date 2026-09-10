import test from "node:test";
import assert from "node:assert/strict";
import { createAuthPort } from "../dist/index.js";
import { createAuthPortReact } from "../dist/react.js";

test("public ESM entry points export supported factories", () => {
  assert.equal(typeof createAuthPort, "function");
  assert.equal(typeof createAuthPortReact, "function");
});

test("public client remains a projection of server authority", async () => {
  const client = createAuthPort({ fetch: async () => ({
    ok: true, status: 200, text: async () => JSON.stringify({ allowed: false }),
  }) });
  assert.equal(await client.authorize("invoice.create"), false);
});
