#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const require = createRequire(import.meta.url);
const supportedPlatforms = [
  "darwin-arm64",
  "darwin-x64",
  "linux-arm64",
  "linux-x64",
];
const platform = `${process.platform}-${process.arch}`;
const override = process.env.AUTHBOUNDRY_CLI_PATH;

function optionalPackageExecutable() {
  try {
    const packageJson = require.resolve(`@authboundry/core-${platform}/package.json`);
    return join(dirname(packageJson), "bin", "authboundry");
  } catch {
    return undefined;
  }
}

const bundledExecutable = join(dirname(fileURLToPath(import.meta.url)), "..", "native", platform, "authboundry");
const candidates = override ? [override] : [optionalPackageExecutable(), bundledExecutable].filter(Boolean);
const executable = candidates.find((candidate) => existsSync(candidate)) || candidates[candidates.length - 1];
const result = spawnSync(executable, process.argv.slice(2), { stdio: "inherit" });
if (result.error) {
  if (result.error.code === "ENOENT") {
    if (override) {
      console.error(`authboundry: AUTHBOUNDRY_CLI_PATH does not exist or is not executable: ${override}`);
    } else {
      console.error(`authboundry: no packaged CLI runtime for ${platform}`);
    }
    console.error(`Supported platforms: ${supportedPlatforms.join(", ")}`);
    console.error("Set AUTHBOUNDRY_CLI_PATH to an authboundry binary for local development or CI.");
  } else {
    console.error(`authboundry: ${result.error.message}`);
  }
  process.exitCode = 1;
} else if (result.signal) {
  process.kill(process.pid, result.signal);
} else {
  process.exitCode = result.status ?? 1;
}
