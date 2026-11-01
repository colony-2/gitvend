// No provisioning: use only the host's preexisting tools. Node is also required by npm tests.
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';

export const baseline = 'ea025082843ef5f3163787a4b134f40c78725e96';
export const checks = [
  { argv: ['make', 'check'], timeout: 1200000, goflags: '-v' },
  { argv: ['make', 'fuzz'], timeout: 600000, goflags: '-v' },
  { argv: ['make', 'build'], timeout: 600000 },
  { argv: ['npm', 'test', '--prefix', 'npm/gitvend'], timeout: 600000 },
  { argv: ['go', 'mod', 'tidy', '-diff'], timeout: 600000 },
];

export function runCommand(argv, { cwd, env = process.env, timeout = 30000 } = {}) {
  return new Promise(resolve => {
    const record = { argv, start: new Date().toISOString(), timeout_ms: timeout,
      stdout: '', stderr: '', exit: null, signal: null, timed_out: false };
    const child = spawn(argv[0], argv.slice(1), { cwd, env, detached: true });
    const kill = () => {
      try { process.kill(-child.pid, 'SIGKILL'); } catch (error) {
        if (error.code !== 'ESRCH') record.kill_error = error.message;
      }
    };
    const timer = setTimeout(() => { record.timed_out = true; kill(); }, timeout);
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', data => { record.stdout += data; });
    child.stderr.on('data', data => { record.stderr += data; });
    child.on('error', error => { record.launch_error = error.message; });
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      // Clean up descendants even if a timed-out leader exits first.
      if (record.timed_out) kill();
      Object.assign(record, { exit: code, signal, end: new Date().toISOString() });
      resolve(record);
    });
  });
}
const ok = r => r.exit === 0 && !r.timed_out && !r.launch_error;
const digest = value => createHash('sha256').update(value).digest('hex');

async function git(root, args) {
  const result = await runCommand(['git', ...args], { cwd: root });
  if (!ok(result)) throw new Error(`git ${args[0]} failed: ${result.stderr}`);
  return result.stdout;
}

export async function snapshot(root) {
  const head = (await git(root, ['rev-parse', 'HEAD'])).trim();
  const index = await git(root, ['ls-files', '-v', '--stage', '-z']);
  const names = (await git(root, ['ls-files', '-z'])).split('\0').filter(Boolean);
  const files = {};
  for (const name of names) {
    const filename = path.join(root, name);
    try {
      const stat = fs.lstatSync(filename);
      files[name] = { mode: stat.mode, hash: stat.isSymbolicLink()
        ? digest(fs.readlinkSync(filename)) : stat.isFile() ? digest(fs.readFileSync(filename)) : 'directory' };
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      files[name] = { missing: true };
    }
  }
  return { head, index, files,
    tracked_diff_hash: digest(await git(root, ['diff', '--binary', '--no-ext-diff', '--no-textconv', 'HEAD', '--'])) };
}

// Discover existing installations only. Never invoke a package manager or toolchain downloader.
function installedGoBins() {
  const bins = ['/usr/local/go/bin', '/opt/go/bin', '/nix/var/nix/profiles/default/bin'];
  try {
    bins.push(...fs.readdirSync('/nix/store')
      .filter(name => /-go-\d+\.\d+(?:\.\d+)?$/.test(name))
      .sort((a, b) => b.slice(b.lastIndexOf('-go-')).localeCompare(
        a.slice(a.lastIndexOf('-go-')), undefined, { numeric: true }))
      .map(name => path.join('/nix/store', name, 'bin')));
  } catch (error) { if (error.code !== 'ENOENT') throw error; }
  return bins;
}

export async function executionEnvironment(env, bins = installedGoBins()) {
  const prepared = { ...env, GOTOOLCHAIN: 'local', GOENV: 'off' };
  const resolution = { source: 'PATH', probes: [], credential_helpers: 'reset for local fixtures; command-line helpers remain usable' };
  const executable = filename => { try { fs.accessSync(filename, fs.constants.X_OK); return fs.statSync(filename).isFile(); } catch { return false; } };
  if (!(env.PATH || '').split(path.delimiter).some(bin => executable(path.join(bin, 'go')))) {
    resolution.source = 'unavailable';
    const native = `${process.platform}/${{ x64: 'amd64', arm64: 'arm64' }[process.arch] || process.arch}`;
    for (const bin of bins) {
      const filename = path.join(bin, 'go');
      if (!executable(filename)) continue;
      const probe = await runCommand([filename, 'version'], { env: prepared });
      resolution.probes.push(probe);
      if (ok(probe) && probe.stdout.trim().endsWith(' ' + native)) {
        prepared.PATH = bin + path.delimiter + (env.PATH || '');
        resolution.source = 'preexisting installation';
        resolution.bin = bin;
        break;
      }
    }
  }
  // Git fixture commands add their disposable helper via -c, after environment config.
  const count = Number(env.GIT_CONFIG_COUNT || '0');
  if (!Number.isSafeInteger(count) || count < 0) throw new Error('Invalid inherited GIT_CONFIG_COUNT');
  prepared.GIT_CONFIG_COUNT = String(count + 1);
  prepared[`GIT_CONFIG_KEY_${count}`] = 'credential.helper';
  prepared[`GIT_CONFIG_VALUE_${count}`] = '';
  return { env: prepared, resolution };
}

export async function verify({ worktree, directory, candidate, outbox, env = process.env }) {
  const evidence = { baseline, candidate, commands: [], tools: [], errors: [],
    mapping: checks.map((c, i) => ({ command: c.argv.join(' '),
      source: i === 4 ? '.github/workflows/release.yaml / build / Check module tidiness' : '.github/workflows/test.yml / test' })),
    omissions: ['Docker Compose startup/health/volumes/recreation', 'other hosts and architectures',
      'CI checkout/setup/caches', 'release packaging/checksums/smoke tests',
      'signing/notarization', 'tagging, publication, registry login and deployment'],
    coverage_note: 'Local fixtures only; no live GitHub or platform parity claim. Test skips are not executed coverage.' };
  let root;
  let cache;
  let toolEnv;
  try {
    root = fs.realpathSync(worktree);
    if (!directory || path.isAbsolute(directory) || directory.split(/[\\/]/).includes('..')) {
      throw new Error('Invalid repository-relative target directory');
    }
    const target = fs.realpathSync(path.resolve(root, directory));
    if ((target !== root && !target.startsWith(root + path.sep)) || !fs.statSync(target).isDirectory()) {
      throw new Error('Target directory escapes checkout or is not a directory');
    }
    const gitRoot = fs.realpathSync((await git(root, ['rev-parse', '--show-toplevel'])).trim());
    if (gitRoot !== root) throw new Error('Worktree must be the managed repository root');
    evidence.before = await snapshot(root);
    if (Number(process.versions.node.split('.')[0]) < 22) throw new Error('Node 22 or newer is required');
    const expected = (await git(root, ['rev-parse', '--verify', `${candidate}^{commit}`])).trim();
    if (expected !== evidence.before.head) throw new Error('Candidate identity does not match HEAD');
    const prepared = await executionEnvironment(env);
    toolEnv = prepared.env;
    evidence.execution_environment = prepared.resolution;
    for (const argv of [['git', '--version'], ['go', 'version'], ['node', '--version'],
      ['npm', '--version'], ['make', '--version'], ['cc', '--version'], ['tar', '--version'], ['uname', '-sm']]) {
      evidence.tools.push(await runCommand(argv, { cwd: root, env: toolEnv }));
    }
    const execPath = (await git(root, ['--exec-path'])).trim();
    try { fs.accessSync(path.join(execPath, 'git-http-backend'), fs.constants.X_OK); }
    catch { evidence.errors.push('Preexisting git-http-backend is unavailable'); }
    if (evidence.tools.some(r => !ok(r))) evidence.errors.push('One or more preexisting tools are unavailable');
    // A fresh cache forces test execution without passing test-only flags to vet.
    cache = fs.mkdtempSync(path.join(os.tmpdir(), 'gitvend-go-cache-'));
    for (const check of checks) {
      const commandEnv = { ...toolEnv, GOTOOLCHAIN: 'local', GOENV: 'off', CGO_ENABLED: '1', GOFLAGS: '', GOCACHE: cache, MAKEFLAGS: '', MFLAGS: '', GNUMAKEFLAGS: '' };
      delete commandEnv.GOOS;
      delete commandEnv.GOARCH;
      if (check.goflags) commandEnv.GOFLAGS = check.goflags;
      const record = await runCommand(check.argv, { cwd: root, env: commandEnv, timeout: check.timeout });
      evidence.commands.push(record);
      if (!ok(record)) evidence.errors.push(`${check.argv.join(' ')} failed`);
    }
    evidence.fuzz_failures = {};
    const generated = (await git(root, ['ls-files', '--others', '--exclude-standard', '-z', '--',
      'internal/policy/testdata/fuzz', 'internal/gitwire/testdata/fuzz', 'internal/jsonutil/testdata/fuzz']))
      .split('\0').filter(Boolean);
    for (const name of generated) {
      const filename = fs.realpathSync(path.join(root, name));
      if (!filename.startsWith(root + path.sep) || !fs.statSync(filename).isFile()) {
        throw new Error('Fuzz diagnostic escapes checkout or is not a file');
      }
      evidence.fuzz_failures[name] = fs.readFileSync(filename).toString('base64');
    }
    const [race, fuzz, build, npm] = evidence.commands;
    evidence.vet = /(?:^|\n)go vet \.\/\.\.\./.test(race.stdout) ? (ok(race) ? 'passed' : 'attempted; inspect log') : 'unattempted';
    if (evidence.vet !== 'passed') evidence.errors.push('Vet did not complete successfully');
    evidence.skips = evidence.commands.flatMap(record => record.stdout.split('\n')
      .filter(line => /--- SKIP:|# SKIP|(?:#|ℹ) skipped /.test(line))
      .map(line => ({ command: record.argv, line })));
    if (!/^=== RUN /m.test(race.stdout)) evidence.errors.push('No executed Go test events observed');
    if ((fuzz.stdout.match(/fuzz: elapsed:/g) || []).length < 3) evidence.errors.push('Three fuzz runs were not observed');
    if (!/^(?:#|ℹ) tests [1-9][0-9]*/m.test(npm.stdout)) evidence.errors.push('No npm tests observed');
    if (ok(build) && ['gitvend', 'jobdb-gitvend-secret-provider'].some(name => !fs.existsSync(path.join(root, 'bin', name)))) {
      evidence.errors.push('Expected native binaries are absent');
    }
  } catch (error) {
    evidence.errors.push(error.message);
  } finally {
    if (cache) {
      try { fs.rmSync(cache, { recursive: true, force: true }); }
      catch (error) { evidence.errors.push(`Owned cache cleanup failed: ${error.message}`); }
    }
    if (root) {
      try {
        evidence.after = await snapshot(root);
        if (evidence.before && JSON.stringify(evidence.before) !== JSON.stringify(evidence.after)) {
          evidence.errors.push('HEAD, tracked worktree or index changed');
        }
      } catch (error) { evidence.errors.push(`Post-check integrity capture failed: ${error.message}`); }
    }
  }
  const status = evidence.errors.length ? 'failed' : 'passed';
  const result = { api_version: 'c2.build-hook/v1', status,
    summary: status === 'passed' ? 'Five Gitvend checks passed; candidate integrity preserved. See evidence.json for coverage and omissions.'
      : `Gitvend verification failed: ${evidence.errors.join('; ')}. See evidence.json.` };
  // Export errors must throw so the operation blocks instead of fabricating a hook result.
  fs.writeFileSync(path.join(outbox, 'evidence.json'), JSON.stringify(evidence, null, 2));
  fs.writeFileSync(path.join(outbox, 'result.json'), JSON.stringify(result, null, 2));
  return result;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  verify({ worktree: process.env.WORKTREE, directory: process.env.DIRECTORY,
    candidate: process.env.CANDIDATE, outbox: process.env.OUTBOX })
    .then(result => process.stdout.write(JSON.stringify(result)))
    .catch(error => { console.error(`Verification finalization failed: ${error.message}`); process.exitCode = 1; });
}
