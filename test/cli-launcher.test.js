import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const launcher = fileURLToPath(new URL("../bin/authboundry.js", import.meta.url));

test("CLI launcher honors AUTHBOUNDRY_CLI_PATH", async () => {
  const dir = await mkdtemp(join(tmpdir(), "authboundry-cli-"));
  try {
    const fakeCli = join(dir, "authboundry");
    await writeFile(fakeCli, '#!/bin/sh\nprintf "override:%s\\n" "$*"\nexit 7\n');
    await chmod(fakeCli, 0o755);

    const result = spawnSync(process.execPath, [launcher, "--help", "status"], {
      env: { ...process.env, AUTHBOUNDRY_CLI_PATH: fakeCli },
      encoding: "utf8",
    });

    assert.equal(result.status, 7);
    assert.equal(result.stdout, "override:--help status\n");
  } finally {
    await rm(dir, { force: true, recursive: true });
  }
});

test("CLI launcher explains supported platforms when the selected runtime is missing", () => {
  const result = spawnSync(process.execPath, [launcher, "--help"], {
    env: { ...process.env, AUTHBOUNDRY_CLI_PATH: "/tmp/authboundry-missing-runtime" },
    encoding: "utf8",
  });

  assert.equal(result.status, 1);
  assert.match(result.stderr, /AUTHBOUNDRY_CLI_PATH/);
  assert.match(result.stderr, /Supported platforms: darwin-arm64, darwin-x64, linux-arm64, linux-x64/);
});
