import assert from "assert";
import { readFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const packageJsonPath = join(__dirname, "..", "package-lock.json");

const lockfile = JSON.parse(readFileSync(packageJsonPath, "utf8"));

const feltdbDep = lockfile.packages["node_modules/@feltdb/core"];

assert(
  feltdbDep,
  "FeltDB core dependency is missing from node_modules or lockfile"
);

const version = feltdbDep.version;
const [major, minor, patch] = version.split(".").map(Number);

assert.strictEqual(
  major,
  0,
  `FeltDB major version must be 0, got ${major} from version ${version}`
);
assert.strictEqual(
  minor,
  10,
  `FeltDB minor version must be 10, got ${minor} from version ${version}`
);
assert.strictEqual(
  patch,
  0,
  `FeltDB patch version must be 0, got ${patch} from version ${version}`
);

console.log(`✓ FeltDB core pinned exactly to 0.10.0 (${version})`);
