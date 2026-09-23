#!/usr/bin/env node

// Adapted from colony-2/c2j; see THIRD_PARTY_NOTICES.md.
"use strict";

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { execFileSync } = require("child_process");
const { get } = require("https");

const { pipeline } = require("stream/promises");

const platforms = {
  "linux:x64": ["Linux", "x86_64"],
  "linux:arm64": ["Linux", "arm64"],
  "darwin:x64": ["Darwin", "x86_64"],
  "darwin:arm64": ["Darwin", "arm64"],
};

function releaseAsset(pkg, platform, arch) {
  const target = platforms[`${platform}:${arch}`];
  if (!target) throw new Error(`Unsupported platform: ${platform}:${arch}`);
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(pkg.version)) {
    throw new Error(`Not a release version: ${pkg.version}`);
  }
  const name = pkg.name.split("/").pop();
  if (name !== "gitvend") throw new Error("Expected gitvend package name");
  return {
    name,
    assetName: `${name}_${pkg.version}_${target[0]}_${target[1]}.tar.gz`,
    baseUrl: `https://github.com/${repositoryPath(pkg)}/releases/download/v${pkg.version}`,
  };
}

async function install({
  packageRoot = path.resolve(__dirname, ".."),
  platform = process.platform,
  arch = process.arch,
  downloadFile = downloadWithRetry,
} = {}) {
  const pkg = JSON.parse(fs.readFileSync(path.join(packageRoot, "package.json"), "utf8"));
  const { name, assetName, baseUrl } = releaseAsset(pkg, platform, arch);
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), `${name}-`));
  const vendorDir = path.join(packageRoot, "vendor");
  let stagedBinary;
  try {
    const archivePath = path.join(tempDir, assetName);
    const checksumsPath = path.join(tempDir, "checksums.txt");
    const extractDir = path.join(tempDir, "extract");
    fs.mkdirSync(extractDir);
    await downloadFile(`${baseUrl}/${assetName}`, archivePath);
    await downloadFile(`${baseUrl}/checksums.txt`, checksumsPath, { maxBytes: 1024 * 1024 });
    verifyChecksum(archivePath, checksumsPath, assetName);
    // Extract only the executable, not documentation or other archive entries.
    execFileSync("tar", ["-xzf", archivePath, "-C", extractDir, name], { stdio: "pipe" });
    const binary = path.join(extractDir, name);
    if (!fs.lstatSync(binary).isFile()) throw new Error("Release binary must be a regular file");
    fs.mkdirSync(vendorDir, { recursive: true });
    stagedBinary = path.join(vendorDir, `.gitvend-${crypto.randomBytes(8).toString("hex")}`);
    fs.copyFileSync(binary, stagedBinary, fs.constants.COPYFILE_EXCL);
    fs.chmodSync(stagedBinary, 0o755);
    fs.renameSync(stagedBinary, path.join(vendorDir, name));
  } finally {
    if (stagedBinary) fs.rmSync(stagedBinary, { force: true });
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
}

function repositoryPath(pkg) {
  const raw =
    typeof pkg.repository === "string" ? pkg.repository : pkg.repository && pkg.repository.url;

  if (!raw) {
    throw new Error("package.json repository is required to locate release assets");
  }

  const match = raw.match(/^(?:git\+)?https:\/\/github\.com\/([A-Za-z0-9_-]+\/[A-Za-z0-9_.-]+?)(?:\.git)?$/);
  if (!match) {
    throw new Error(`Unsupported repository URL for release assets: ${raw}`);
  }

  return match[1];
}

async function downloadWithRetry(url, destination, options = {}) {
  let lastError;

  for (let attempt = 1; attempt <= 5; attempt += 1) {
    try {
      await download(url, destination, options);
      return;
    } catch (error) {
      lastError = error;
      if (attempt === 5) {
        break;
      }
      await delay(attempt * 1000);
    }
  }

  throw lastError;
}

function download(url, destination, { request = get, redirects = 5, timeout = 30000, maxBytes = 256 * 1024 * 1024 } = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:") throw new Error("Release downloads require HTTPS");
    const req = request(parsed, (response) => {
      if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
        response.resume();
        if (redirects === 0) return reject(new Error("Too many release download redirects"));
        let location;
        try { location = new URL(response.headers.location, parsed).href; }
        catch (error) { reject(error); return; }
        download(location, destination, { request, redirects: redirects - 1, timeout, maxBytes }).then(resolve, reject);
        return;
      }
      if (response.statusCode !== 200) {
        response.resume();
        reject(new Error(`Failed to download ${url}: HTTP ${response.statusCode}`));
        return;
      }
      let size = 0;
      response.on("data", (chunk) => {
        size += chunk.length;
        if (size > maxBytes) response.destroy(new Error("Release download exceeds size limit"));
      });
      const file = fs.createWriteStream(destination, { mode: 0o600 });
      pipeline(response, file).then(resolve, reject);
    });
    req.setTimeout(timeout, () => req.destroy(new Error("Release download timed out")));
    req.on("error", reject);
  });
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function verifyChecksum(archive, checksums, assetName) {
  const matches = fs
    .readFileSync(checksums, "utf8")
    .split(/\r?\n/)
    .map((line) => line.trim().split(/\s+/))
    .filter((parts) => parts[1] === assetName);
  const expected = matches[0];

  if (matches.length !== 1 || !/^[a-f0-9]{64}$/.test(expected[0])) {
    throw new Error(`Missing, duplicate or invalid checksum for ${assetName}`);
  }

  const actual = crypto.createHash("sha256").update(fs.readFileSync(archive)).digest("hex");
  if (actual !== expected[0]) {
    throw new Error(`Checksum mismatch for ${assetName}`);
  }
}

module.exports = { install, releaseAsset, repositoryPath, download, verifyChecksum };
if (require.main === module) {
  install().catch((error) => {
    console.error(error.message || error);
    process.exitCode = 1;
  });
}
