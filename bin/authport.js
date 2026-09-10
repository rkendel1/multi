#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const platform = `${process.platform}-${process.arch}`;
const executable = join(dirname(fileURLToPath(import.meta.url)), "..", "native", platform, "authport");
const result = spawnSync(executable, process.argv.slice(2), { stdio: "inherit" });
if (result.error) {
  if (result.error.code === "ENOENT") {
    console.error(`authport: no packaged CLI runtime for ${platform}`);
  } else {
    console.error(`authport: ${result.error.message}`);
  }
  process.exitCode = 1;
} else if (result.signal) {
  process.kill(process.pid, result.signal);
} else {
  process.exitCode = result.status ?? 1;
}
