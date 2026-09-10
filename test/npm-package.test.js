import test from "node:test";
import assert from "node:assert/strict";
import { createAuthBoundry } from "../dist/index.js";
import { createAuthBoundryReact } from "../dist/react.js";
import packageMetadata from "../package.json" with { type: "json" };

test("public ESM entry points export supported factories", () => {
  assert.equal(typeof createAuthBoundry, "function");
  assert.equal(typeof createAuthBoundryReact, "function");
});

test("legacy TypeScript resolvers can locate public subpath declarations", () => {
  assert.equal(packageMetadata.typesVersions["*"].react[0], "./dist/react.d.ts");
  assert.equal(packageMetadata.typesVersions["*"].client[0], "./dist/client.d.ts");
});

test("public client remains a projection of server authority", async () => {
  const client = createAuthBoundry({ fetch: async () => ({
    ok: true, status: 200, text: async () => JSON.stringify({ allowed: false }),
  }) });
  assert.equal(await client.authorize("invoice.create"), false);
});
