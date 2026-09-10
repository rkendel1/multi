#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";

const require = createRequire(import.meta.url);
const packageJson = require.resolve("@authboundry/core/package.json");
const executable = join(dirname(packageJson), "bin", "authboundry.js");
const result = spawnSync(process.execPath, [executable, ...process.argv.slice(2)], {
  stdio: "inherit",
});

if (result.error) {
  console.error(`authboundry: ${result.error.message}`);
  process.exitCode = 1;
} else if (result.signal) {
  process.kill(process.pid, result.signal);
} else {
  process.exitCode = result.status ?? 1;
}
