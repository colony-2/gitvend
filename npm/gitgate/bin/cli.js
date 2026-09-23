#!/usr/bin/env node

// Adapted from colony-2/c2j; see THIRD_PARTY_NOTICES.md.
"use strict";

const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");

const packageRoot = path.resolve(__dirname, "..");
const packageJson = require(path.join(packageRoot, "package.json"));
const packageName = packageJson.name.split("/").pop();
const binaryPath = path.join(packageRoot, "vendor", packageName);

if (!fs.existsSync(binaryPath)) {
  console.error(
    `${packageName} binary is missing. Reinstall the package or run npm rebuild ${packageJson.name}.`
  );
  process.exit(1);
}

const child = spawn(binaryPath, process.argv.slice(2), {
  stdio: "inherit",
});

// The gateway is a long-running process; forward shutdown and reload signals.
const handlers = new Map();
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  const handler = () => child.kill(signal);
  handlers.set(signal, handler);
  process.on(signal, handler);
}
child.on("error", (error) => {
  console.error(error.message);
  process.exit(1);
});
child.on("exit", (status, signal) => {
  for (const [name, handler] of handlers) process.removeListener(name, handler);
  if (signal) process.kill(process.pid, signal);
  else process.exit(status === null ? 1 : status);
});
