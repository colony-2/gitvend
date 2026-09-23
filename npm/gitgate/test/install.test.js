"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const crypto = require("node:crypto");
const { execFileSync, spawnSync, spawn } = require("node:child_process");
const { install, releaseAsset, repositoryPath, download } = require("../scripts/postinstall.js");

const pkg = { ...require("../package.json"), version: "1.2.3" };
function temporary(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "gitgate-test-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}

test("release asset names match all four build targets", () => {
  for (const [platform, arch, suffix] of [
    ["linux", "x64", "Linux_x86_64"], ["linux", "arm64", "Linux_arm64"],
    ["darwin", "x64", "Darwin_x86_64"], ["darwin", "arm64", "Darwin_arm64"],
  ]) {
    assert.deepEqual(releaseAsset(pkg, platform, arch), {
      name: "gitgate",
      assetName: `gitgate_1.2.3_${suffix}.tar.gz`,
      baseUrl: "https://github.com/colony-2/gitgate/releases/download/v1.2.3",
    });
  }
  assert.throws(() => releaseAsset(pkg, "win32", "x64"), /Unsupported platform/);
  assert.throws(() => releaseAsset({ ...pkg, version: "../bad" }, "linux", "x64"), /release version/);
  assert.throws(() => repositoryPath({ repository: "https://evil.example/github.com/a/b" }), /Unsupported repository/);
});

test("installer verifies checksums, installs a runnable binary and preserves it on failure", async (t) => {
  const root = temporary(t);
  const source = path.join(root, "source");
  const packageRoot = path.join(root, "package");
  fs.mkdirSync(source);
  fs.mkdirSync(packageRoot);
  fs.writeFileSync(path.join(packageRoot, "package.json"), JSON.stringify(pkg));
  fs.cpSync(path.join(__dirname, "../bin"), path.join(packageRoot, "bin"), { recursive: true });
  fs.writeFileSync(path.join(source, "gitgate"), '#!/bin/sh\nprintf "arg=%s\\n" "$@"\nexit 7\n', { mode: 0o755 });
  const archive = path.join(root, "release.tar.gz");
  execFileSync("tar", ["-czf", archive, "-C", source, "gitgate"]);
  const bytes = fs.readFileSync(archive);
  const hash = crypto.createHash("sha256").update(bytes).digest("hex");
  let checksum = `${hash}  gitgate_1.2.3_Linux_x86_64.tar.gz\n`;
  const destinations = [];
  const options = {
    packageRoot, platform: "linux", arch: "x64",
    downloadFile: async (url, dest) => {
      assert.match(url, /^https:\/\/github.com\/colony-2\/gitgate\/releases\/download\/v1.2.3\//);
      destinations.push(dest);
      fs.writeFileSync(dest, url.endsWith("checksums.txt") ? checksum : bytes);
    },
  };
  await install(options);
  const binary = path.join(packageRoot, "vendor/gitgate");
  assert.equal(fs.statSync(binary).mode & 0o777, 0o755);
  const result = spawnSync(process.execPath, [path.join(packageRoot, "bin/cli.js"), "version", "space value"], { encoding: "utf8" });
  assert.equal(result.status, 7);
  assert.equal(result.stdout, "arg=version\narg=space value\n");
  const original = fs.readFileSync(binary);
  for (const bad of [checksum.replace(hash, "0".repeat(64)), "", checksum + checksum]) {
    checksum = bad;
    await assert.rejects(install(options), /checksum/i);
    assert.deepEqual(fs.readFileSync(binary), original);
  }
  for (const dest of destinations) assert.equal(fs.existsSync(dest), false, "temporary download cleaned up");
  fs.unlinkSync(binary);
  const missing = spawnSync(process.execPath, [path.join(packageRoot, "bin/cli.js")], { encoding: "utf8" });
  assert.equal(missing.status, 1);
  assert.match(missing.stderr, /npm rebuild @colony2\/gitgate/);
});

test("download handles redirects, status errors, truncation, limits and timeouts", async (t) => {
  const root = temporary(t);
  const server = http.createServer((req, res) => {
    switch (req.url) {
      case "/redirect": res.writeHead(302, { location: "/ok" }).end(); break;
      case "/loop": res.writeHead(302, { location: "/loop" }).end(); break;
      case "/downgrade": res.writeHead(302, { location: "http://example.invalid" }).end(); break;
      case "/ok": res.end("archive contents"); break;
      case "/slow": break;
      case "/truncated":
        res.writeHead(200, { "content-length": "100" });
        res.flushHeaders();
        res.end("short");
        break;
      default: res.writeHead(404).end();
    }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => { server.closeAllConnections(); server.close(); });
  // Exercise real sockets while keeping production downloads HTTPS-only.
  const request = (url, handler) => {
    const local = new URL(url);
    local.protocol = "http:";
    local.hostname = "127.0.0.1";
    local.port = server.address().port;
    return http.get(local, handler);
  };
  const dest = path.join(root, "download");
  const options = { request, timeout: 100 };
  await download("https://fixture/redirect", dest, options);
  assert.equal(fs.readFileSync(dest, "utf8"), "archive contents");
  await assert.rejects(download("https://fixture/missing", dest, options), /HTTP 404/);
  await assert.rejects(download("https://fixture/loop", dest, options), /Too many/);
  await assert.rejects(download("https://fixture/downgrade", dest, options), /HTTPS/);
  await assert.rejects(download("https://fixture/ok", dest, { ...options, maxBytes: 2 }), /size limit/);
  await assert.rejects(download("https://fixture/slow", dest, options), /timed out/);
  await assert.rejects(download("https://fixture/truncated", dest, options));
  await assert.rejects(download("http://fixture/ok", dest, options), /HTTPS/);
});

test("installer rejects symlink binaries", async (t) => {
  const root = temporary(t);
  fs.writeFileSync(path.join(root, "package.json"), JSON.stringify(pkg));
  fs.symlinkSync("/bin/sh", path.join(root, "gitgate"));
  const archive = path.join(root, "archive.tar.gz");
  execFileSync("tar", ["-czf", archive, "-C", root, "gitgate"]);
  const bytes = fs.readFileSync(archive);
  const hash = crypto.createHash("sha256").update(bytes).digest("hex");
  await assert.rejects(install({
    packageRoot: root, platform: "linux", arch: "x64",
    downloadFile: async (url, dest) => fs.writeFileSync(dest, url.endsWith("checksums.txt")
      ? `${hash}  gitgate_1.2.3_Linux_x86_64.tar.gz\n` : bytes),
  }), /regular file/);
  assert.equal(fs.existsSync(path.join(root, "vendor/gitgate")), false);
});

test("launcher forwards reload and shutdown signals to the server", { timeout: 5000 }, async (t) => {
  const root = temporary(t);
  fs.writeFileSync(path.join(root, "package.json"), JSON.stringify(pkg));
  fs.cpSync(path.join(__dirname, "../bin"), path.join(root, "bin"), { recursive: true });
  fs.mkdirSync(path.join(root, "vendor"));
  fs.writeFileSync(path.join(root, "vendor/gitgate"), `#!${process.execPath}
process.on("SIGHUP", () => console.log("reloaded"));
process.on("SIGTERM", () => process.exit(0));
setInterval(() => {}, 1000);
console.log("ready");
`, { mode: 0o755 });
  const child = spawn(process.execPath, [path.join(root, "bin/cli.js")], { stdio: ["ignore", "pipe", "pipe"] });
  t.after(() => { if (child.exitCode === null) child.kill("SIGTERM"); });
  let output = "";
  let sentReload = false;
  child.stdout.on("data", (data) => {
    output += data;
    if (output.includes("ready") && !sentReload) {
      sentReload = true;
      child.kill("SIGHUP");
    }
    if (output.includes("reloaded")) child.kill("SIGTERM");
  });
  const result = await new Promise((resolve, reject) => {
    child.on("error", reject);
    child.on("exit", (code, signal) => resolve({ code, signal }));
  });
  assert.deepEqual(result, { code: 0, signal: null });
  assert.match(output, /ready\nreloaded\n/);
});
