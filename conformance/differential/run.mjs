// Differential fuzzer: the SAME mutated containers go to the Rust reader
// (crates/hide-object/examples/differential_oracle.rs) and to the independent
// Node reader (conformance/node/verify.mjs). Any disagreement about
// accept/reject — or, when both accept, about plaintext, filename, media type,
// metadata-extension count or signer — is a finding.
//
//   cargo build -p hide-object --features test-vectors --example differential_oracle
//   node conformance/differential/run.mjs [--iterations 2000] [--seed 1] [--oracle <path>] [--keep]
//
// Two mutation families:
//   raw        byte-level edits of the seed corpus; almost all die at the MAC,
//              so they exercise the parsers' early (pre-authentication) checks.
//   structured containers re-assembled from parts with a known CEK, re-MACed
//              and re-encrypted, so the mutation reaches the semantic checks.

import { spawnSync } from "node:child_process";
import { createCipheriv, createHash, hkdfSync } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdir, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  Rejection,
  decrypt,
  encodeCbor,
  encrypt,
  newSigningIdentity,
  rebuild,
  transcript10,
  transcriptLegacy,
} from "../node/verify.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "../..");
const vectors = join(root, "conformance/vectors");

// ---------------------------------------------------------------------------
// Arguments
// ---------------------------------------------------------------------------

function parseArgs(argv) {
  const args = { iterations: 2000, seed: 1, oracle: undefined, keep: false };
  for (let i = 0; i < argv.length; i++) {
    const flag = argv[i];
    if (flag === "--iterations") args.iterations = Number(argv[++i]);
    else if (flag === "--seed") args.seed = Number(argv[++i]);
    else if (flag === "--oracle") args.oracle = argv[++i];
    else if (flag === "--keep") args.keep = true;
    else throw new Error(`unknown argument ${flag}`);
  }
  if (!Number.isInteger(args.iterations) || args.iterations < 1) throw new Error("--iterations must be a positive integer");
  if (!Number.isInteger(args.seed) || args.seed < 0) throw new Error("--seed must be a non-negative integer");
  return args;
}

// ---------------------------------------------------------------------------
// Deterministic PRNG (splitmix32) — mutation choices depend only on --seed
// ---------------------------------------------------------------------------

function prng(seed) {
  let state = (seed ^ 0x9e3779b9) >>> 0;
  const next = () => {
    state = (state + 0x9e3779b9) >>> 0;
    let z = state;
    z = Math.imul(z ^ (z >>> 16), 0x85ebca6b) >>> 0;
    z = Math.imul(z ^ (z >>> 13), 0xc2b2ae35) >>> 0;
    return (z ^ (z >>> 16)) >>> 0;
  };
  const int = (n) => next() % n;
  return {
    int,
    range: (lo, hi) => lo + int(hi - lo + 1),
    chance: (p) => next() / 2 ** 32 < p,
    pick: (list) => list[int(list.length)],
    bytes: (n) => {
      const out = Buffer.alloc(n);
      for (let i = 0; i < n; i++) out[i] = next() & 0xff;
      return out;
    },
  };
}

// ---------------------------------------------------------------------------
// Small wire helpers (verify.mjs keeps these private)
// ---------------------------------------------------------------------------

const sha256 = (value) => createHash("sha256").update(value).digest("hex");
const concat = (...parts) => Buffer.concat(parts.map((part) => Buffer.from(part)));
const label = (value) => Buffer.from(`HIDE/0.1 ${value}`, "ascii");
const MAGIC = Buffer.from("484944450d0a1a0a", "hex");
const CONTEXT_1_0 = Buffer.from("HIDE/1.0 container", "ascii");
const CONTEXT_LEGACY = Buffer.from("HIDE/0.5 container", "ascii");

function cborHead(major, value) {
  const n = BigInt(value);
  if (n < 24n) return Buffer.from([(major << 5) | Number(n)]);
  const width = n < 1n << 8n ? 1 : n < 1n << 16n ? 2 : n < 1n << 32n ? 4 : 8;
  const out = Buffer.alloc(1 + width);
  out[0] = (major << 5) | { 1: 24, 2: 25, 4: 26, 8: 27 }[width];
  for (let i = width, v = n; i >= 1; i--, v >>= 8n) out[i] = Number(v & 0xffn);
  return out;
}

/// A CBOR map in exactly the given entry order, duplicates allowed. Used when
/// a mutation deliberately breaks key order or uniqueness, which a canonical
/// encoder would silently repair.
function encodeEntries(entries, raw) {
  if (!raw) return encodeCbor(new Map(entries));
  return concat(cborHead(5, entries.length), ...entries.flatMap(([k, v]) => [encodeCbor(k), encodeCbor(v)]));
}

function u64(value) {
  const out = Buffer.alloc(8);
  out.writeBigUInt64BE(BigInt(value));
  return out;
}

function sealMetadata(cek, objectId, metadataBytes) {
  const key = Buffer.from(hkdfSync("sha256", cek, objectId, label("metadata"), 32));
  const cipher = createCipheriv("chacha20-poly1305", key, Buffer.alloc(12), { authTagLength: 16 });
  cipher.setAAD(concat(label("metadata"), objectId, [0, 1]));
  return concat(cipher.update(metadataBytes), cipher.final(), cipher.getAuthTag());
}

// ---------------------------------------------------------------------------
// Bases: valid unsigned containers with a known CEK
// ---------------------------------------------------------------------------

/// The X-Wing encapsulation is random, so the wrapped stanza for each base is
/// cached on disk: with the cache present, every unsigned mutant of a seed is
/// byte-reproducible. (ML-DSA signing is randomised, so signed mutants are
/// reproducible in structure, not bytes; findings are saved verbatim anyway.)
async function loadBases(publicKey, recipientSeed, cachePath) {
  const cache = existsSync(cachePath) ? JSON.parse(await readFile(cachePath, "utf8")) : {};
  const specs = [
    { name: "hello", plaintext: Buffer.from("hello world"), filename: "hello.txt", mediaType: "text/plain" },
    { name: "empty", plaintext: Buffer.alloc(0), filename: "empty.txt", mediaType: "text/plain" },
    { name: "one-record", plaintext: Buffer.alloc(65536, 0x61), filename: "full.bin", mediaType: "application/octet-stream" },
    { name: "two-records", plaintext: Buffer.alloc(65537, 0x62), filename: "two.bin", mediaType: "application/octet-stream" },
  ];
  const bases = [];
  let dirty = false;
  for (const spec of specs) {
    const objectId = createHash("sha256").update(`differential object ${spec.name}`).digest();
    const cek = createHash("sha256").update(`differential cek ${spec.name}`).digest();
    let stanza = cache[spec.name] && [1, Buffer.from(cache[spec.name].enc, "hex"), Buffer.from(cache[spec.name].wrapped, "hex")];
    if (!stanza) {
      const container = await encrypt(publicKey, spec.plaintext, { cek, objectId, salt: Buffer.alloc(16), filename: spec.filename, mediaType: spec.mediaType });
      stanza = (await decrypt(container, recipientSeed)).stanzas[0];
      cache[spec.name] = { enc: stanza[1].toString("hex"), wrapped: stanza[2].toString("hex") };
      dirty = true;
    }
    bases.push({ ...spec, objectId, cek, stanza });
  }
  if (dirty) await writeFile(cachePath, JSON.stringify(cache, null, 1));
  return bases;
}

// ---------------------------------------------------------------------------
// Structured mutants
// ---------------------------------------------------------------------------

const META = Symbol("sealed metadata");

function baseSpec(base) {
  return {
    base,
    preamble: { major: 0, minor: 1, kind: 1, flags: 0 },
    header: [[1, 1], [2, base.objectId], [3, [base.stanza]], [4, META], [5, []]],
    rawHeader: false,
    metadata: [[1, base.filename], [2, base.mediaType]],
    rawMetadata: false,
    metadataBytes: undefined,
    plaintext: base.plaintext,
    sign: undefined,
    postSign: [],
    notes: [],
  };
}

const entry = (spec, key) => spec.header.find(([k]) => k === key);
const stanzasOf = (spec) => {
  const e = entry(spec, 3);
  return e && Array.isArray(e[1]) ? e[1] : undefined;
};

function valueFrom(rng, pool) {
  const kind = rng.pick(pool);
  switch (kind) {
    case "bstr0": return Buffer.alloc(0);
    case "bstr1": return rng.bytes(1);
    case "bstr32": return rng.bytes(32);
    case "bstr65536": return Buffer.alloc(65536, 0x41);
    case "bstr65537": return Buffer.alloc(65537, 0x42);
    case "tstr": return "x";
    case "uint": return 5;
    case "array": return [];
    case "map": return new Map();
    default: throw new Error(kind);
  }
}
const EXT_VALUES = ["bstr0", "bstr1", "bstr32", "bstr32", "bstr65536", "bstr65537", "tstr", "uint", "array", "map"];
const HEADER_KEYS = [0, 6, 7, 32, 63, 64, 65, 100, 1000, 65534, 65535, 65536, 70000, 2 ** 32, 2n ** 63n];
const METADATA_KEYS = [0, 3, 4, 5, 6, 7, 63, 64, 65, 1000, 65535, 65536, 2 ** 32];
const FILENAMES = [
  "..", ".", "a.", "a ", " a", "CON", "con", "con.txt", "CON.tar.gz", "COM1", "com1.txt", "COM0", "COM10", "LPT9", "lpt1.x",
  "NUL", "AUX.", "PRN.txt", "a/b", "a\\b", "a:b", "a*b", "a?b", "a<b", "a|b", "a\"b", "a\u0000b", "a\u0001", "\u001f",
  "a\u007f", "a\u0085b", "a\u009f", "a\u00a0", "a\u2028b", "a\u200bb", "\u017fON", "ſ", "é.txt", "日本.txt", "😀.txt",
  "x".repeat(255), "x".repeat(256), "é".repeat(127) + "x", "é".repeat(128), "😀".repeat(63) + "abc", "😀".repeat(64),
  "", " ", "normal.txt", ".hidden", "a..b", "COM¹", "CON\u0085",
];
const MEDIA_TYPES = ["", "a", "text/plain", "x".repeat(255), "x".repeat(256), "t\u00ebxt", "a\tb", "a b", "a\u007f", "~", " ", "\u0000", "text/plain; charset=utf-8"];

/// Each mutation edits the spec in place and returns a short description.
const MUTATIONS = [
  // Preamble (§1)
  [3, (s, r) => { s.preamble.minor = r.pick([0, 1, 2, 3, 7, 254, 255]); return `minor=${s.preamble.minor}`; }],
  [3, (s, r) => { s.preamble.flags = r.pick([0, 1, 2, 3, 0x40, 0x80, 0xff]); return `flags=${s.preamble.flags}`; }],
  [1, (s, r) => { s.preamble.kind = r.pick([0, 2, 255]); return `kind=${s.preamble.kind}`; }],
  [1, (s, r) => { s.preamble.major = r.pick([1, 255]); return `major=${s.preamble.major}`; }],
  // Header extensions (§2.1)
  [6, (s, r) => {
    const key = r.pick(HEADER_KEYS);
    const value = valueFrom(r, EXT_VALUES);
    s.header = s.header.filter(([k]) => k !== key);
    s.header.push([key, value]);
    return `header ext ${key}=${describe(value)}`;
  }],
  [3, (s, r) => {
    const n = r.pick([15, 16, 16, 17, 17, 18]);
    for (let i = 0; i < n; i++) s.header.push([64 + i * 7, r.bytes(r.int(4))]);
    return `header exts x${n}`;
  }],
  [2, (s, r) => {
    const key = r.pick([1, 2, 3, 4, 5]);
    s.header = s.header.filter(([k]) => k !== key);
    return `remove header key ${key}`;
  }],
  [2, (s, r) => {
    if (s.header.length < 2) return "swap (noop)";
    const i = r.int(s.header.length - 1);
    [s.header[i], s.header[i + 1]] = [s.header[i + 1], s.header[i]];
    s.rawHeader = true;
    return `swap header entries ${i},${i + 1} (raw order)`;
  }],
  [1, (s, r) => {
    const e = r.pick(s.header);
    s.header.push([e[0], e[1]]);
    s.rawHeader = true;
    return `duplicate header key ${String(e[0])}`;
  }],
  [1, (s, r) => { entry(s, 1) && (entry(s, 1)[1] = r.pick([0, 2, 65535, "1", Buffer.from([1])])); return `suite=${describe(entry(s, 1)?.[1])}`; }],
  [1, (s, r) => { entry(s, 2) && (entry(s, 2)[1] = r.bytes(r.pick([0, 31, 33]))); return "object_id length"; }],
  // Recipient stanzas (§2.2)
  [8, (s, r) => {
    const stanzas = stanzasOf(s);
    if (!stanzas) return "stanza (no array)";
    const tag = r.pick([0, 1, 2, 3, 2, 255, 256, 65535, 65536, 2 ** 32, "t", Buffer.from([2])]);
    const items = r.pick([0, 0, 1, 2, 3, 7, 8, 9]);
    const fields = [];
    for (let i = 0; i < items; i++) {
      const len = r.pick([0, 1, 32, 48, 1120, 65536, 65537]);
      fields.push(r.chance(0.1) ? r.pick(["s", 7, []]) : Buffer.alloc(len, i));
    }
    const at = r.int(stanzas.length + 1);
    stanzas.splice(at, 0, [tag, ...fields]);
    return `stanza [${describe(tag)}, ${fields.map(describe).join(",")}] at ${at}`;
  }],
  [2, (s, r) => {
    const stanzas = stanzasOf(s);
    if (!stanzas) return "stanza (no array)";
    const shape = r.pick([
      [1, Buffer.alloc(1120, 1), Buffer.alloc(47, 2)],
      [1, Buffer.alloc(1120, 1)],
      [1, Buffer.alloc(1119, 1), Buffer.alloc(48, 2)],
      [1, Buffer.alloc(1120, 1), Buffer.alloc(48, 2), Buffer.alloc(0)],
      [1, "x", Buffer.alloc(48)],
    ]);
    stanzas.splice(r.int(stanzas.length + 1), 0, shape);
    return `tag-1 stanza wrong shape ${shape.map(describe).join(",")}`;
  }],
  [2, (s, r) => {
    const stanzas = stanzasOf(s);
    if (!stanzas) return "disguise (no array)";
    const tag = r.pick([0, 2, 65535]);
    const i = stanzas.findIndex((x) => x === s.base.stanza);
    if (i >= 0) stanzas[i] = [tag, s.base.stanza[1], s.base.stanza[2]];
    return `disguise X-Wing stanza as tag ${tag}`;
  }],
  [2, (s, r) => {
    const stanzas = stanzasOf(s);
    if (!stanzas) return "fill (no array)";
    const total = r.pick([63, 64, 65]);
    while (stanzas.length < total) stanzas.splice(r.int(stanzas.length + 1), 0, [2]);
    return `stanza count ${total}`;
  }],
  [1, (s, r) => {
    const e = entry(s, 3);
    if (e) e[1] = r.pick([[], Buffer.alloc(3), 1, [s.base.stanza, "x"]]);
    return `key 3=${describe(e?.[1])}`;
  }],
  [1, (s, r) => {
    const stanzas = stanzasOf(s);
    if (!stanzas || stanzas.length < 2) return "reverse (noop)";
    stanzas.reverse();
    void r;
    return "reverse stanzas";
  }],
  // Public signature array (§2.3)
  [4, (s, r) => {
    const e = entry(s, 5);
    if (!e) return "key 5 (removed)";
    const bogus = () => r.pick([
      [0, Buffer.alloc(1984), Buffer.alloc(3373)],
      [2, Buffer.alloc(1984), Buffer.alloc(3373)],
      [1, Buffer.alloc(1983), Buffer.alloc(3373)],
      [1, Buffer.alloc(1985), Buffer.alloc(3373)],
      [1, Buffer.alloc(1984), Buffer.alloc(3372)],
      [1, Buffer.alloc(1984), Buffer.alloc(3374)],
      [1, Buffer.alloc(1984)],
      [1, Buffer.alloc(1984), Buffer.alloc(3373), Buffer.alloc(0)],
      [1, Buffer.alloc(1984, 7), Buffer.alloc(3373, 9)],
      [],
    ]);
    e[1] = r.pick([[bogus()], [bogus(), bogus()], Buffer.alloc(0), 0, new Map()]);
    return `key 5=${describe(e[1])}`;
  }],
  // Metadata (§4)
  [8, (s, r) => {
    const name = r.pick(FILENAMES);
    s.metadata = s.metadata.filter(([k]) => k !== 1);
    s.metadata.unshift([1, name]);
    return `filename ${JSON.stringify(name).slice(0, 40)} (${Buffer.byteLength(name)}B)`;
  }],
  [4, (s, r) => {
    const value = r.pick(MEDIA_TYPES);
    s.metadata = s.metadata.filter(([k]) => k !== 2);
    s.metadata.push([2, value]);
    return `media_type ${JSON.stringify(value).slice(0, 40)}`;
  }],
  [2, (s, r) => {
    const key = r.pick([1, 2]);
    const value = r.pick([Buffer.from("a"), 7, [], new Map()]);
    s.metadata = s.metadata.filter(([k]) => k !== key);
    s.metadata.push([key, value]);
    return `metadata ${key}=${describe(value)} (wrong type)`;
  }],
  [2, (s, r) => { const key = r.pick([1, 2]); s.metadata = s.metadata.filter(([k]) => k !== key); return `remove metadata ${key}`; }],
  [5, (s, r) => {
    const key = r.pick(METADATA_KEYS);
    const value = key === 3 ? r.pick([[1, Buffer.alloc(1984), Buffer.alloc(3373)], [2, Buffer.alloc(1984), Buffer.alloc(3373)], Buffer.alloc(3)]) : valueFrom(r, EXT_VALUES);
    s.metadata = s.metadata.filter(([k]) => k !== key);
    s.metadata.push([key, value]);
    return `metadata ${key}=${describe(value)}`;
  }],
  [2, (s, r) => {
    const n = r.pick([15, 16, 17, 18]);
    for (let i = 0; i < n; i++) s.metadata.push([64 + i, r.bytes(r.int(3))]);
    return `metadata exts x${n}`;
  }],
  [1, (s, r) => {
    if (s.metadata.length < 2) return "metadata swap (noop)";
    s.metadata.reverse();
    s.rawMetadata = true;
    void r;
    return "metadata reversed (raw order)";
  }],
  [1, (s, r) => {
    s.metadataBytes = r.pick([
      encodeCbor([]), encodeCbor(1), encodeCbor("x"), Buffer.from([0xa0]), Buffer.alloc(0), Buffer.from([0xa1, 0x01]),
      Buffer.from([0xa1, 0x18, 0x01, 0x61, 0x61]), Buffer.from([0xa2, 0x01, 0x61, 0x61, 0x01, 0x61, 0x62]),
      concat(encodeCbor(new Map([[1, "a"]])), [0x00]), Buffer.alloc(262145, 0),
    ]);
    return `metadata bytes ${s.metadataBytes.subarray(0, 8).toString("hex")} (${s.metadataBytes.length}B)`;
  }],
  // Payload
  [2, (s, r) => { s.plaintext = r.pick([Buffer.alloc(0), Buffer.from("x"), Buffer.alloc(65535, 1), Buffer.alloc(65536, 2), Buffer.alloc(65537, 3)]); return `plaintext ${s.plaintext.length}B`; }],
  // Signatures (§2.3, §7)
  [10, (s, r) => {
    s.sign = {
      placement: r.pick(["public", "confidential"]),
      transcript: r.chance(0.8) ? "1.0" : "legacy",
      markSigned: r.chance(0.9),
    };
    if (s.sign.transcript === "legacy" && r.chance(0.7)) { s.preamble.minor = 2; s.preamble.flags = 0; }
    return `sign ${s.sign.placement} ${s.sign.transcript}${s.sign.markSigned ? "" : " (flag not set)"}`;
  }],
  [4, (s, r) => {
    if (!s.sign) s.sign = { placement: r.pick(["public", "confidential"]), transcript: "1.0", markSigned: true };
    const what = r.pick(["strip", "both", "corrupt-sig", "corrupt-key", "small-order-key", "change-ext", "add-ext", "reorder-stanzas", "change-filename", "change-plaintext", "unflag", "minor-bump", "add-unknown-stanza"]);
    s.postSign.push(what);
    return `post-sign ${what}`;
  }],
];

const TOTAL_WEIGHT = MUTATIONS.reduce((sum, [w]) => sum + w, 0);
function pickMutation(rng) {
  let n = rng.int(TOTAL_WEIGHT);
  for (const [w, fn] of MUTATIONS) {
    if (n < w) return fn;
    n -= w;
  }
  throw new Error("unreachable");
}

function describe(value) {
  if (Buffer.isBuffer(value)) return `bstr(${value.length})`;
  if (typeof value === "string") return `tstr(${Buffer.byteLength(value)})`;
  if (Array.isArray(value)) return `[${value.map(describe).join(",")}]`;
  if (value instanceof Map) return `map(${value.size})`;
  return String(value);
}

/// Every edge value on its own, applied to a valid base. Random stacking of
/// mutations rarely leaves one edge case alone on an otherwise valid
/// container, and a rule is only compared when nothing earlier rejects; so
/// these run on every invocation, whatever the seed.
function sweepSpecs(bases) {
  const [hello] = bases;
  const out = [];
  const add = (description, edit, base = hello) => {
    const spec = baseSpec(base);
    edit(spec);
    out.push({ spec, description });
  };
  for (const name of FILENAMES) add(`filename ${JSON.stringify(name).slice(0, 40)}`, (s) => { s.metadata = [[1, name], ...s.metadata.filter(([k]) => k !== 1)]; });
  for (const value of MEDIA_TYPES) add(`media_type ${JSON.stringify(value).slice(0, 40)}`, (s) => { s.metadata = [...s.metadata.filter(([k]) => k !== 2), [2, value]]; });
  for (const key of HEADER_KEYS) {
    for (const kind of ["bstr0", "bstr32", "bstr65536", "bstr65537", "tstr", "uint"]) {
      const value = valueFrom({ pick: () => kind, bytes: (n) => Buffer.alloc(n, 0x33) }, [kind]);
      add(`header ext ${key}=${kind}`, (s) => { s.header.push([key, value]); });
    }
  }
  for (const key of METADATA_KEYS.filter((k) => k !== 3)) {
    for (const kind of ["bstr0", "bstr32", "bstr65536", "bstr65537", "tstr"]) {
      const value = valueFrom({ pick: () => kind, bytes: (n) => Buffer.alloc(n, 0x33) }, [kind]);
      add(`metadata ${key}=${kind}`, (s) => { s.metadata.push([key, value]); });
    }
  }
  for (const n of [15, 16, 17]) {
    add(`header exts x${n}`, (s) => { for (let i = 0; i < n; i++) s.header.push([64 + i, Buffer.from([i])]); });
    add(`metadata exts x${n}`, (s) => { for (let i = 0; i < n; i++) s.metadata.push([64 + i, Buffer.from([i])]); });
  }
  for (const minor of [0, 1, 2, 3, 255]) {
    for (const flags of [0, 1, 2, 0x80]) add(`minor=${minor} flags=${flags}`, (s) => { s.preamble.minor = minor; s.preamble.flags = flags; });
  }
  for (const tag of [0, 2, 65535, 65536]) {
    for (const items of [0, 1, 2, 7, 8]) {
      add(`unknown stanza tag ${tag} items ${items}`, (s) => { stanzasOf(s).push([tag, ...Array.from({ length: items }, (_, i) => Buffer.alloc(i === 1 ? 65536 : 3, i))]); });
    }
  }
  add("unknown stanza field 65537", (s) => { stanzasOf(s).push([2, Buffer.alloc(65537)]); });
  add("stanza count 64", (s) => { while (stanzasOf(s).length < 64) stanzasOf(s).push([2]); });
  add("stanza count 65", (s) => { while (stanzasOf(s).length < 65) stanzasOf(s).push([2]); });
  for (const placement of ["public", "confidential"]) {
    for (const transcript of ["1.0", "legacy"]) {
      add(`sign ${placement} ${transcript}`, (s) => {
        s.sign = { placement, transcript, markSigned: true };
        if (transcript === "legacy") s.preamble.minor = 2;
      });
      // A signature that verifies over an UNSIGNED preamble: only the
      // "signature present but flag clear" rule can refuse it.
      add(`sign ${placement} ${transcript} (flag never set)`, (s) => {
        s.sign = { placement, transcript, markSigned: false };
      });
      for (const post of ["strip", "both", "corrupt-sig", "small-order-key", "add-ext", "add-unknown-stanza", "change-filename", "unflag", "minor-bump"]) {
        add(`sign ${placement} ${transcript} + ${post}`, (s) => {
          s.sign = { placement, transcript, markSigned: true };
          if (transcript === "legacy") s.preamble.minor = 2;
          s.postSign.push(post);
        });
      }
    }
  }
  for (const base of bases) add(`plain ${base.name}`, () => {}, base);
  return out;
}

async function buildStructured(spec, identity, rng) {
  const { base } = spec;
  const preamble12 = () => concat(MAGIC, [spec.preamble.major, spec.preamble.minor, spec.preamble.kind, spec.preamble.flags]);
  const post = new Set(spec.postSign);
  if (spec.sign) {
    if (spec.sign.markSigned && spec.sign.transcript === "1.0") spec.preamble.flags |= 1;
    const stanzas = stanzasOf(spec) ?? [];
    const headerExtensions = spec.header
      .filter(([k, v]) => typeof k === "number" && k > 5 && Buffer.isBuffer(v))
      .sort(([a], [b]) => a - b);
    const metadataBase = spec.metadataBytes ?? encodeCbor(new Map(spec.metadata.filter(([k]) => k !== 3)));
    const legacy = spec.sign.transcript === "legacy";
    let message;
    try {
      message = legacy
        ? transcriptLegacy({ objectId: base.objectId, stanzas: stanzas.filter(Array.isArray).map((x) => x.map((f) => (Buffer.isBuffer(f) ? f : Buffer.from(String(f))))), metadataBase, plaintext: spec.plaintext })
        : transcript10({ preamble12: preamble12(), objectId: base.objectId, stanzas: stanzas.filter((x) => Array.isArray(x) && typeof x[0] === "number" && x.slice(1).every(Buffer.isBuffer)), headerExtensions, metadataBase, plaintext: spec.plaintext });
    } catch {
      message = Buffer.from("unsignable");
    }
    const context = legacy ? CONTEXT_LEGACY : CONTEXT_1_0;
    let signature = [1, identity.verifyingKey, identity.sign(concat(u64(context.length), context, message))];
    if (post.has("corrupt-sig")) { const sig = Buffer.from(signature[2]); sig[rng.int(sig.length)] ^= 1 << rng.int(8); signature = [1, signature[1], sig]; }
    if (post.has("corrupt-key")) { const key = Buffer.from(signature[1]); key[rng.int(key.length)] ^= 1 << rng.int(8); signature = [1, key, signature[2]]; }
    if (post.has("small-order-key")) { const key = Buffer.from(signature[1]); key.fill(0, 0, 32); key[0] = 1; signature = [1, key, signature[2]]; }
    const toPublic = spec.sign.placement === "public" || post.has("both");
    const toConfidential = spec.sign.placement === "confidential" || post.has("both");
    if (!post.has("strip")) {
      if (toPublic) {
        const e = entry(spec, 5);
        if (e && Array.isArray(e[1])) e[1] = [...e[1], signature];
      }
      if (toConfidential) spec.metadata = [...spec.metadata.filter(([k]) => k !== 3), [3, signature]];
    }
    if (post.has("change-ext")) {
      const e = spec.header.find(([k, v]) => typeof k === "number" && k >= 64 && Buffer.isBuffer(v) && v.length > 0);
      if (e) { e[1] = Buffer.from(e[1]); e[1][0] ^= 1; } else spec.header.push([64, Buffer.from("post")]);
    }
    if (post.has("add-ext")) spec.header.push([4096, Buffer.from("added after signing")]);
    if (post.has("reorder-stanzas")) stanzasOf(spec)?.reverse();
    if (post.has("add-unknown-stanza")) stanzasOf(spec)?.push([7, Buffer.from("late")]);
    if (post.has("change-filename")) spec.metadata = [[1, "changed.txt"], ...spec.metadata.filter(([k]) => k !== 1)];
    if (post.has("change-plaintext")) spec.plaintext = concat(spec.plaintext, "!");
    if (post.has("unflag")) spec.preamble.flags &= ~1;
    if (post.has("minor-bump")) spec.preamble.minor = 3;
  }

  const metadataBytes = spec.metadataBytes ?? encodeEntries(spec.metadata, spec.rawMetadata);
  const sealed = sealMetadata(base.cek, base.objectId, metadataBytes);
  const header = spec.header.map(([k, v]) => [k, v === META ? sealed : v]);
  const protectedBytes = encodeEntries(header, spec.rawHeader);
  return rebuild({
    preamble: preamble12(),
    protectedBytes,
    cek: base.cek,
    salt: rng.bytes(16),
    plaintext: spec.plaintext,
    objectId: base.objectId,
  });
}

// ---------------------------------------------------------------------------
// Raw mutants
// ---------------------------------------------------------------------------

function mutateRaw(input, rng) {
  let bytes = Buffer.from(input);
  const steps = [];
  const count = rng.pick([1, 1, 1, 2, 3]);
  for (let i = 0; i < count; i++) {
    const where = () => (rng.chance(0.4) ? rng.int(Math.min(bytes.length, 64) || 1) : rng.int(bytes.length || 1));
    switch (rng.pick(["flip", "flip", "set", "insert", "delete", "truncate", "append", "header_len", "header_len", "preamble"])) {
      case "flip": { const at = where(); if (bytes.length) bytes[at] ^= 1 << rng.int(8); steps.push(`flip@${at}`); break; }
      case "set": { const at = where(); if (bytes.length) bytes[at] = rng.pick([0, 0xff, 0x18, 0x19, 0x1a, 0x1b, 0x9f, 0xbf, rng.int(256)]); steps.push(`set@${at}`); break; }
      case "insert": { const at = where(); const n = rng.pick([1, 1, 2, 4, 16]); bytes = concat(bytes.subarray(0, at), rng.bytes(n), bytes.subarray(at)); steps.push(`insert${n}@${at}`); break; }
      case "delete": { const at = where(); const n = rng.pick([1, 1, 2, 4, 16]); bytes = concat(bytes.subarray(0, at), bytes.subarray(at + n)); steps.push(`delete${n}@${at}`); break; }
      case "truncate": { const at = rng.int(bytes.length + 1); bytes = bytes.subarray(0, at); steps.push(`truncate@${at}`); break; }
      case "append": { const n = rng.pick([1, 5, 16, 21]); bytes = concat(bytes, rng.bytes(n)); steps.push(`append${n}`); break; }
      case "header_len": {
        if (bytes.length >= 16) {
          const old = bytes.readUInt32BE(12);
          const value = rng.pick([0, 1, old - 1, old + 1, old + 16, 1048576, 1048577, 0xffffffff, rng.int(2 ** 32)]) >>> 0;
          bytes = Buffer.from(bytes);
          bytes.writeUInt32BE(value, 12);
          steps.push(`header_len=${value}`);
        }
        break;
      }
      case "preamble": {
        if (bytes.length >= 12) {
          const at = rng.range(8, 11);
          bytes = Buffer.from(bytes);
          bytes[at] = rng.pick([0, 1, 2, 3, 0x80, 0xff]);
          steps.push(`preamble[${at}]=${bytes[at]}`);
        }
        break;
      }
    }
  }
  return { bytes, steps };
}

// ---------------------------------------------------------------------------
// Comparing verdicts
// ---------------------------------------------------------------------------

function rustClass(error) {
  const io = /^Io\(.*kind: (\w+)/.exec(error);
  return io ? `Io(${io[1]})` : error;
}

async function nodeVerdict(bytes, seed) {
  try {
    const result = await decrypt(bytes, seed);
    const filename = result.metadata.get(1);
    const mediaType = result.metadata.get(2);
    return {
      ok: true,
      plaintext_sha256: sha256(result.plaintext),
      plaintext_len: result.plaintext.length,
      filename: typeof filename === "string" ? filename : null,
      media_type: typeof mediaType === "string" ? mediaType : null,
      extensions: result.metadataExtensions.length,
      signer_sha256: result.signer ? sha256(result.signer) : null,
    };
  } catch (error) {
    if (error instanceof Rejection) return { ok: false, code: error.code, detail: error.message };
    return { ok: false, code: `THREW ${error?.name ?? "?"}`, detail: String(error?.message ?? error), crashed: true };
  }
}

const FIELDS = ["plaintext_sha256", "plaintext_len", "filename", "media_type", "extensions", "signer_sha256"];

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const oracle = args.oracle ?? join(root, "target/debug/examples", process.platform === "win32" ? "differential_oracle.exe" : "differential_oracle");
  if (!existsSync(oracle)) {
    console.error(`oracle not found at ${oracle}\nbuild it: cargo build -p hide-object --features test-vectors --example differential_oracle`);
    process.exit(2);
  }
  const rng = prng(args.seed);
  const recipientSeed = await readFile(join(vectors, "recipient.test-secret"));
  const publicKey = await readFile(join(vectors, "recipient.test-public"));
  const work = join(root, ".copilot-tmp/differential");
  const out = join(work, String(args.seed));
  await rm(out, { recursive: true, force: true });
  await mkdir(out, { recursive: true });

  const seeds = [];
  for (const dir of [vectors, join(vectors, "rejections")]) {
    for (const name of (await readdir(dir)).sort()) {
      if (name.endsWith(".hide")) seeds.push({ name: relative(vectors, join(dir, name)).replaceAll("\\", "/"), bytes: await readFile(join(dir, name)) });
    }
  }
  const bases = await loadBases(publicKey, recipientSeed, join(work, "bases.json"));
  const identity = newSigningIdentity();

  // Generate. The seed corpus itself goes in first, unmutated, as a baseline.
  const cases = [];
  const emit = async (family, description, bytes) => {
    const file = join(out, `${String(cases.length).padStart(6, "0")}.hide`);
    await writeFile(file, bytes);
    cases.push({ file, family, description });
  };
  for (const seed of seeds) await emit("seed", seed.name, seed.bytes);
  const sweepRng = prng(0x5eed);
  for (const { spec, description } of sweepSpecs(bases)) {
    await emit("sweep", `${spec.base.name}: ${description}`, await buildStructured(spec, identity, sweepRng));
  }
  const sweepCount = cases.length - seeds.length;
  for (let i = 0; i < args.iterations; i++) {
    if (rng.chance(0.3)) {
      const seed = rng.pick(seeds);
      const { bytes, steps } = mutateRaw(seed.bytes, rng);
      await emit("raw", `${seed.name}: ${steps.join(" ")}`, bytes);
    } else {
      const base = rng.pick(bases);
      const spec = baseSpec(base);
      const notes = [];
      const n = rng.pick([1, 1, 2, 2, 3]);
      for (let k = 0; k < n; k++) notes.push(pickMutation(rng)(spec, rng));
      let bytes;
      try {
        bytes = await buildStructured(spec, identity, rng);
      } catch (error) {
        notes.push(`(build failed: ${error.message})`);
        continue;
      }
      await emit("structured", `${base.name}: ${notes.join("; ")}`, bytes);
    }
  }

  // Rust, once, over the whole directory.
  const started = Date.now();
  const run = spawnSync(oracle, [out], { maxBuffer: 1 << 30, encoding: "utf8" });
  if (run.status !== 0) {
    console.error(`oracle exited ${run.status}\n${run.stderr}`);
    process.exit(2);
  }
  const rust = new Map();
  for (const line of run.stdout.split("\n").filter(Boolean)) {
    const verdict = JSON.parse(line);
    rust.set(resolve(verdict.path), verdict);
  }
  const rustMs = Date.now() - started;

  const findingsDir = join(here, "findings");
  const tally = { cases: cases.length, bothAccept: 0, bothReject: 0, disagreements: 0, nodeCrashes: 0 };
  const byFamily = {};
  const mapping = new Map();
  const disagreements = [];
  const nodeStarted = Date.now();
  for (const c of cases) {
    const bytes = await readFile(c.file);
    const r = rust.get(resolve(c.file));
    if (!r) throw new Error(`oracle printed nothing for ${c.file}`);
    const n = await nodeVerdict(bytes, recipientSeed);
    const family = (byFamily[c.family] ??= { total: 0, bothAccept: 0, bothReject: 0, disagree: 0 });
    family.total++;
    if (n.crashed) tally.nodeCrashes++;
    let problem;
    if (r.ok && n.ok) {
      const diffs = FIELDS.filter((f) => r[f] !== n[f]).map((f) => `${f}: rust=${JSON.stringify(r[f])} node=${JSON.stringify(n[f])}`);
      if (diffs.length) problem = `both accept but differ — ${diffs.join("; ")}`;
      else { tally.bothAccept++; family.bothAccept++; }
    } else if (!r.ok && !n.ok) {
      tally.bothReject++;
      family.bothReject++;
      const key = `${rustClass(r.error)}\t${n.code}`;
      mapping.set(key, (mapping.get(key) ?? 0) + 1);
    } else {
      problem = r.ok ? `Rust ACCEPTS, Node rejects (${n.detail})` : `Node ACCEPTS, Rust rejects (${r.error})`;
    }
    if (problem) {
      tally.disagreements++;
      family.disagree++;
      const digest = sha256(bytes);
      await mkdir(findingsDir, { recursive: true });
      await writeFile(join(findingsDir, `${digest}.hide`), bytes);
      await writeFile(join(findingsDir, `${digest}.json`), JSON.stringify({ seed: args.seed, family: c.family, mutation: c.description, problem, rust: r, node: n }, null, 1));
      disagreements.push({ digest, problem, description: c.description });
    }
  }
  const nodeMs = Date.now() - nodeStarted;

  console.log(`seed ${args.seed}: ${args.iterations} iterations -> ${tally.cases} containers (incl. ${seeds.length} unmutated seeds, ${sweepCount} sweep)`);
  console.log(`  rust ${rustMs} ms (one process), node ${nodeMs} ms`);
  for (const [family, f] of Object.entries(byFamily)) {
    console.log(`  ${family.padEnd(10)} total ${String(f.total).padStart(5)}  both-accept ${String(f.bothAccept).padStart(5)}  both-reject ${String(f.bothReject).padStart(5)}  disagree ${f.disagree}`);
  }
  console.log(`  accepted by both: ${tally.bothAccept}`);
  console.log(`  rejected by both: ${tally.bothReject}`);
  console.log(`  node threw a non-Rejection: ${tally.nodeCrashes}`);
  console.log(`  disagreements: ${tally.disagreements}`);

  // Error classes are named differently on each side; show how they pair up.
  const rows = [...mapping].sort(([a], [b]) => a.localeCompare(b));
  const rustClasses = new Map();
  for (const [key, count] of rows) {
    const [rc] = key.split("\t");
    rustClasses.set(rc, (rustClasses.get(rc) ?? 0) + (count > 0 ? 1 : 0));
  }
  console.log("\n  error-class mapping (both reject) — rust -> node : count");
  for (const [key, count] of rows) {
    const [rc, nc] = key.split("\t");
    const flag = rustClasses.get(rc) > 1 ? "  (warning: rust class maps to several node codes)" : "";
    console.log(`    ${rc.padEnd(34)} -> ${nc.padEnd(22)} ${String(count).padStart(5)}${flag}`);
  }

  if (disagreements.length) {
    console.log("\n  DISAGREEMENTS");
    for (const d of disagreements) console.log(`    findings/${d.digest}.hide\n      ${d.description}\n      ${d.problem}`);
  }
  if (!args.keep && !disagreements.length) await rm(out, { recursive: true, force: true });
  process.exit(disagreements.length ? 1 : 0);
}

await main();
