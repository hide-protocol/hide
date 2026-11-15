// Fails when about.toml accepts a licence that deny.toml does not allow.
//
// cargo-deny is the gate that decides which licences may enter the dependency
// graph; cargo-about only writes the notices. If about.toml accepted more than
// the gate allows, a dependency under an unreviewed licence would get a tidy
// notice instead of a failed build, most easily in the desktop graph, which
// the gate did not cover at all before 0.10.0. The reverse direction is
// reported but not fatal: a licence the gate allows and about.toml lacks makes
// `cargo about generate --fail` stop by itself the day a crate uses it.
//
//   usage: node scripts/licences/check-accepted.mjs

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

// Reads `key = [ "a", "b", ... ]` from a TOML file, optionally only inside one
// [table]. Both files keep these arrays as plain string lists with comments,
// which is all this needs to understand.
function stringArray(file, key, table) {
  let text = readFileSync(join(root, file), "utf8").replace(/\r\n/g, "\n");
  if (table) {
    const start = text.indexOf(`\n[${table}]\n`);
    if (start === -1) {
      throw new Error(`${file}: no [${table}] table`);
    }
    const rest = text.slice(start + 1);
    const next = rest.slice(1).search(/\n\[[^\]]+\]\n/);
    text = next === -1 ? rest : rest.slice(0, next + 1);
  }
  const match = text.match(new RegExp(`(?:^|\\n)${key}\\s*=\\s*\\[([^\\]]*)\\]`));
  if (!match) {
    throw new Error(`${file}: no ${key} = [...] array`);
  }
  const values = [];
  for (const line of match[1].split("\n")) {
    const code = line.replace(/#.*$/, "");
    for (const quoted of code.matchAll(/"([^"]+)"/g)) {
      values.push(quoted[1]);
    }
  }
  if (values.length === 0) {
    throw new Error(`${file}: ${key} is empty`);
  }
  return values;
}

const accepted = stringArray("about.toml", "accepted");
const allowed = stringArray("deny.toml", "allow", "licenses");

const notAllowed = accepted.filter((licence) => !allowed.includes(licence));
const notAccepted = allowed.filter((licence) => !accepted.includes(licence));

console.log(`about.toml accepts ${accepted.length} licences, deny.toml allows ${allowed.length}`);
if (notAccepted.length > 0) {
  console.log(`allowed by deny.toml but not listed in about.toml: ${notAccepted.join(", ")}`);
}
if (notAllowed.length > 0) {
  console.error(
    `about.toml accepts licences that deny.toml does not allow: ${notAllowed.join(", ")}\n` +
      "Add them to [licenses].allow in deny.toml deliberately, or remove them from about.toml.",
  );
  process.exit(1);
}
