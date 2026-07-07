"use strict";
// Reads a JS/TS source file path from argv[2], parses it with vendored acorn,
// and emits JSON findings for evasion patterns that a raw-text regex scan
// cannot see: dynamic call targets (obj[computed]()), sensitive globals
// reached via bracket notation, and eval/Function/child_process/require
// invocations whose name or arguments are assembled from string
// concatenation, String.fromCharCode, or base64 rather than written literally.
const fs = require("fs");
const path = require("path");
const acorn = require("./acorn_vendor.js");

const SENSITIVE_NAMES = new Set([
  "eval", "Function", "require", "child_process", "exec", "execSync",
  "spawn", "spawnSync", "execFile", "execFileSync",
]);

const SENSITIVE_SUBSTRINGS = [
  "eval", "function", "require", "child_process", "exec", "spawn",
  "process", "curl", "wget", "base64", "fromcharcode",
];

// Flat, scope-unaware constant table: name -> foldable value, populated by a
// pre-pass over every VariableDeclarator whose initializer is itself
// foldable. Ambiguous (reassigned/duplicate) names are dropped rather than
// guessed at -- this is a best-effort heuristic pass, not a real dataflow
// analysis, so it only ever adds confidence, never a hard false-negative gate
// (regex findings still stand on their own).
let CONST_TABLE = new Map();

function collectConstants(node) {
  if (!node || typeof node.type !== "string") return;
  if (node.type === "VariableDeclarator" && node.id.type === "Identifier" && node.init) {
    const name = node.id.name;
    if (CONST_TABLE.has(name)) {
      CONST_TABLE.set(name, undefined); // seen twice -- ambiguous, poison it
    } else {
      const folded = foldConst(node.init, false);
      CONST_TABLE.set(name, folded);
    }
  }
  for (const key in node) {
    if (key === "parent" || key === "loc" || key === "range" || key === "start" || key === "end") continue;
    const value = node[key];
    if (Array.isArray(value)) {
      for (const child of value) {
        if (child && typeof child.type === "string") collectConstants(child);
      }
    } else if (value && typeof value.type === "string") {
      collectConstants(value);
    }
  }
}

function foldConst(node, useTable = true) {
  if (!node) return null;
  switch (node.type) {
    case "Identifier":
      if (useTable && CONST_TABLE.has(node.name)) {
        const value = CONST_TABLE.get(node.name);
        return value === undefined ? null : value;
      }
      return null;
    case "Literal":
      return typeof node.value === "string" || typeof node.value === "number" ? node.value : null;
    case "TemplateLiteral":
      if (node.expressions.length === 0) {
        return node.quasis.map((q) => q.value.cooked).join("");
      }
      return null;
    case "BinaryExpression": {
      if (node.operator !== "+") return null;
      const left = foldConst(node.left, useTable);
      const right = foldConst(node.right, useTable);
      if (left === null || right === null) return null;
      return `${left}${right}`;
    }
    case "CallExpression": {
      const callee = node.callee;
      if (callee.type === "MemberExpression" && !callee.computed &&
          callee.property.type === "Identifier" && callee.property.name === "fromCharCode") {
        const codes = node.arguments.map((arg) => foldConst(arg, useTable));
        if (codes.every((c) => typeof c === "number")) {
          return String.fromCharCode(...codes);
        }
      }
      return null;
    }
    default:
      return null;
  }
}

function isSuspiciousString(value) {
  if (typeof value !== "string") return false;
  const lowered = value.toLowerCase();
  return SENSITIVE_SUBSTRINGS.some((needle) => lowered.includes(needle));
}

function describeNode(node) {
  if (node.type === "Identifier") return node.name;
  if (node.type === "MemberExpression") {
    const obj = describeNode(node.object);
    if (!node.computed && node.property.type === "Identifier") {
      return `${obj}.${node.property.name}`;
    }
    return `${obj}[...]`;
  }
  return node.type;
}

function walk(node, parent, findings, source) {
  if (!node || typeof node.type !== "string") return;

  if (node.type === "CallExpression") {
    const callee = node.callee;

    // obj[computed](...) where the computed property isn't a plain literal --
    // e.g. window[a](...) after `a` was built via concatenation elsewhere.
    if (callee.type === "MemberExpression" && callee.computed && callee.property.type !== "Literal") {
      const folded = foldConst(callee.property);
      findings.push({
        rule: "ast-dynamic-call-target",
        line: node.loc ? node.loc.start.line : null,
        detail: `Call target resolved via computed member access: ${describeNode(callee)}(...)` +
          (folded !== null ? ` (folds to "${folded}")` : ""),
        severity: folded !== null && isSuspiciousString(folded) ? "HIGH" : "MEDIUM",
      });
    }

    // Direct eval/Function/require/exec-family calls whose callee name is
    // itself computed via string-concat/template/fromCharCode, i.e. the
    // literal token "eval(" never appears in source at all.
    if (callee.type === "Identifier" && SENSITIVE_NAMES.has(callee.name)) {
      const suspiciousArg = node.arguments.find((arg) => {
        if (arg.type === "Literal" || (arg.type === "TemplateLiteral" && arg.expressions.length === 0)) {
          return false; // plain literal argument -- regex already sees this
        }
        const folded = foldConst(arg);
        return folded !== null && isSuspiciousString(folded);
      });
      if (suspiciousArg) {
        const folded = foldConst(suspiciousArg);
        findings.push({
          rule: "ast-constructed-dynamic-argument",
          line: node.loc ? node.loc.start.line : null,
          detail: `${callee.name}(...) receives an argument assembled at runtime (folds to "${folded}") rather than a literal`,
          severity: "HIGH",
        });
      }
    }
  }

  // window["eval"], global["require"], globalThis["child_process"] etc:
  // bracket notation reaching a sensitive global by a literal string key.
  // Regex catches `eval(` but not `win["e"+"val"]` style renamed access.
  if (node.type === "MemberExpression" && node.computed) {
    const folded = foldConst(node.property);
    if (typeof folded === "string" && SENSITIVE_NAMES.has(folded) && node.property.type !== "Literal") {
      findings.push({
        rule: "ast-bracket-notation-sensitive-access",
        line: node.loc ? node.loc.start.line : null,
        detail: `Bracket-notation access resolves to sensitive name "${folded}" via non-literal expression`,
        severity: "HIGH",
      });
    }
  }

  for (const key in node) {
    if (key === "parent" || key === "loc" || key === "range" || key === "start" || key === "end") continue;
    const value = node[key];
    if (Array.isArray(value)) {
      for (const child of value) {
        if (child && typeof child.type === "string") walk(child, node, findings, source);
      }
    } else if (value && typeof value.type === "string") {
      walk(value, node, findings, source);
    }
  }
}

function parseWithFallback(source) {
  const baseOptions = { ecmaVersion: "latest", locations: true, allowHashBang: true, allowReturnOutsideFunction: true, allowImportExportEverywhere: true, allowAwaitOutsideFunction: true };
  try {
    return acorn.parse(source, { ...baseOptions, sourceType: "module" });
  } catch (moduleErr) {
    try {
      return acorn.parse(source, { ...baseOptions, sourceType: "script" });
    } catch (scriptErr) {
      throw scriptErr;
    }
  }
}

function main() {
  const filePath = process.argv[2];
  if (!filePath) {
    process.stdout.write(JSON.stringify({ error: "usage: walker.js <file>" }));
    process.exit(2);
  }
  let source;
  try {
    source = fs.readFileSync(filePath, "utf-8");
  } catch (err) {
    process.stdout.write(JSON.stringify({ error: `read failed: ${err.message}` }));
    process.exit(1);
  }

  let ast;
  try {
    ast = parseWithFallback(source);
  } catch (err) {
    process.stdout.write(JSON.stringify({ error: `parse failed: ${err.message}`, findings: [] }));
    process.exit(0);
  }

  CONST_TABLE = new Map();
  const findings = [];
  try {
    collectConstants(ast);
    walk(ast, null, findings, source);
  } catch (err) {
    process.stdout.write(JSON.stringify({ error: `walk failed: ${err.message}`, findings: [] }));
    process.exit(0);
  }

  process.stdout.write(JSON.stringify({ findings }));
  process.exit(0);
}

main();
