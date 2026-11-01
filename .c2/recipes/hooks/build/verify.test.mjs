import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { verify, runCommand, snapshot, checks, executionEnvironment } from './verify.mjs';

const source = execFileSync('git', ['rev-parse', '--show-toplevel'], { encoding: 'utf8' }).trim();
const git = (root, ...args) => execFileSync('git', args, { cwd: root, encoding: 'utf8' }).trim();
async function fixture(t, mode = '') {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'gitvend-hook-'));
  t.after(() => fs.rmSync(temporary, { recursive: true, force: true }));
  const root = path.join(temporary, 'repo');
  execFileSync('git', ['clone', '--quiet', '--shared', source, root]);
  const bin = path.join(temporary, 'tools');
  const outbox = path.join(temporary, 'out');
  fs.mkdirSync(bin); fs.mkdirSync(outbox);
  const tool = `#!${process.execPath}
const fs = require('fs'); const path = require('path');
const name = path.basename(process.argv[1]); const args = process.argv.slice(2);
if (args[0] === '--version' || args[0] === 'version') { console.log(name + ' fixture version'); process.exit(0); }
if (name === 'make') {
  if (args[0] === 'check') {
    if (process.env.FIXTURE_MODE === 'empty') process.exit(0);
    if (process.env.FIXTURE_MODE === 'timeout') { console.log('owned timeout'); setInterval(()=>{},1000); return; }
    console.log('go test -race ./...'); console.log('=== RUN TestFixture');
    console.log('--- SKIP: TestFixtureSkip');
    if (process.env.FIXTURE_MODE === 'fail') { console.error('controlled original diagnostic'); process.exit(17); }
    if (process.env.FIXTURE_MODE === 'empty') process.exit(0);
    if (process.env.FIXTURE_MODE === 'mutate') fs.appendFileSync('README.md', 'mutation');
    if (process.env.FIXTURE_MODE === 'stage') {
      fs.appendFileSync('README.md', 'staged mutation'); require('child_process').execFileSync('git', ['add', 'README.md']);
    }
    console.log('go vet ./...');
  }
  if (args[0] === 'fuzz' && process.env.FIXTURE_MODE === 'fuzzfail') {
    fs.mkdirSync('internal/policy/testdata/fuzz/FuzzCompile', {recursive:true});
    fs.writeFileSync('internal/policy/testdata/fuzz/FuzzCompile/fixture', 'controlled fuzz input');
    process.exit(7);
  }
  if (args[0] === 'fuzz') console.log('fuzz: elapsed: 15s\\nfuzz: elapsed: 15s\\nfuzz: elapsed: 15s');
  if (args[0] === 'build') {
    fs.mkdirSync('bin', { recursive: true });
    for (const name of ['gitvend', 'jobdb-gitvend-secret-provider']) fs.writeFileSync('bin/' + name, 'fixture');
  }
}
if (name === 'npm') console.log('# tests 3');
if (name === 'go' && process.env.FIXTURE_MODE === 'tidy') { console.error('module diff'); process.exit(1); }
`;
  for (const name of ['make', 'npm', 'go', 'cc', 'tar']) {
    fs.writeFileSync(path.join(bin, name), tool, { mode: 0o755 });
  }
  const config = { worktree: root, directory: '.', candidate: git(root, 'rev-parse', 'HEAD'), outbox,
    env: { ...process.env, PATH: `${bin}:${process.env.PATH}`, FIXTURE_MODE: mode } };
  const run = async () => {
    const result = await verify(config);
    return { result, evidence: JSON.parse(fs.readFileSync(path.join(outbox, 'evidence.json'))) };
  };
  return { root, config, run, bin };
}

test('five-command fixture success retains logs, skips, outputs and integrity', async t => {
  const f = await fixture(t);
  const { result, evidence } = await f.run();
  assert.equal(result.status, 'passed');
  assert.equal(evidence.commands.length, 5);
  assert.deepEqual(evidence.before, evidence.after);
  assert.equal(evidence.vet, 'passed');
  assert.equal(evidence.skips.length, 1);
  assert.equal(evidence.tools.length, 8);
});

test('failure preserves original exit, unattempted vet and independent successes', async t => {
  const f = await fixture(t, 'fail');
  const { result, evidence } = await f.run();
  assert.equal(result.status, 'failed');
  assert.equal(evidence.commands[0].exit, 17);
  assert.match(evidence.commands[0].stderr, /controlled original diagnostic/);
  assert.equal(evidence.vet, 'unattempted');
  assert.equal(evidence.commands[4].exit, 0);
  assert.deepEqual(evidence.before, evidence.after);
});

for (const mode of ['mutate', 'stage']) test(`${mode} detects content and index changes despite existing dirty status`, async t => {
  const f = await fixture(t, mode);
  fs.appendFileSync(path.join(f.root, 'README.md'), 'already dirty');
  if (mode === 'stage') git(f.root, 'add', 'README.md');
  const { result, evidence } = await f.run();
  assert.equal(result.status, 'failed');
  assert.ok(evidence.errors.includes('HEAD, tracked worktree or index changed'));
  assert.match(fs.readFileSync(path.join(f.root, 'README.md'), 'utf8'), /mutation/);
  if (mode === 'stage') assert.notEqual(evidence.before.index, evidence.after.index);
});

for (const directory of ['../', '/tmp', 'escape']) test(`rejects directory ${directory}`, async t => {
  const f = await fixture(t);
  fs.symlinkSync(os.tmpdir(), path.join(f.root, 'escape'));
  f.config.directory = directory;
  const { result, evidence } = await f.run();
  assert.equal(result.status, 'failed');
  assert.equal(evidence.commands.length, 0);
});

test('candidate mismatch executes no checks and preserves HEAD', async t => {
  const f = await fixture(t);
  const before = await snapshot(f.root);
  f.config.candidate = '0000000000000000000000000000000000000000';
  const { result, evidence } = await f.run();
  assert.equal(result.status, 'failed');
  assert.equal(evidence.commands.length, 0);
  assert.deepEqual(await snapshot(f.root), before);
});

test('missing tools and launches cannot pass; all independent checks recorded', async t => {
  const f = await fixture(t);
  f.config.env.PATH = f.bin;
  // Real git is needed for integrity; absolute symlink does not provision any tool.
  fs.symlinkSync(execFileSync('which', ['git'], { encoding: 'utf8' }).trim(), path.join(f.bin, 'git'));
  fs.unlinkSync(path.join(f.bin, 'npm'));
  const { result, evidence } = await f.run();
  assert.equal(result.status, 'failed');
  assert.match(evidence.commands[3].launch_error, /ENOENT/);
  assert.equal(evidence.commands.length, 5);
});

test('module drift fails with diagnostics and preserves module sources', async t => {
  const f = await fixture(t, 'tidy');
  const { result, evidence } = await f.run();
  assert.equal(result.status, 'failed');
  assert.equal(evidence.commands[4].exit, 1);
  assert.match(evidence.commands[4].stderr, /module diff/);
  assert.deepEqual(evidence.before, evidence.after);
});

test('timeout terminates owned descendants and retains output', async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gitvend-timeout-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const marker = path.join(dir, 'survivor');
  const script = `require('child_process').spawn(process.execPath, ['-e', ${JSON.stringify(`setTimeout(() => require('fs').writeFileSync(${JSON.stringify(marker)}, 'alive'), 500)`)}], {stdio:'inherit'}); console.log('before timeout'); setInterval(()=>{},1000);`;
  const r = await runCommand([process.execPath, '-e', script], { timeout: 200 });
  assert.equal(r.timed_out, true);
  assert.match(r.stdout, /before timeout/);
  await new Promise(resolve => setTimeout(resolve, 600));
  assert.equal(fs.existsSync(marker), false);
});

test('artifact finalization errors throw rather than manufacture result', async t => {
  const f = await fixture(t);
  f.config.outbox = path.join(f.config.outbox, 'missing');
  await assert.rejects(f.run(), /ENOENT/);
});


test('empty required suite cannot pass', async t => {
  const f = await fixture(t, 'empty');
  const { result, evidence } = await f.run();
  assert.equal(result.status, 'failed');
  assert.ok(evidence.errors.includes('No executed Go test events observed'));
});

test('required command timeout fails and independent commands still execute', async t => {
  const f = await fixture(t, 'timeout');
  const saved = checks[0].timeout;
  checks[0].timeout = 200;
  try {
    const { result, evidence } = await f.run();
    assert.equal(result.status, 'failed');
    assert.equal(evidence.commands[0].timed_out, true);
    assert.match(evidence.commands[0].stdout, /owned timeout/);
    assert.equal(evidence.commands[4].exit, 0);
  } finally { checks[0].timeout = saved; }
});


test('generated fuzz failures remain in checkout and exported diagnostics', async t => {
  const f = await fixture(t, 'fuzzfail');
  const { result, evidence } = await f.run();
  assert.equal(result.status, 'failed');
  const name = 'internal/policy/testdata/fuzz/FuzzCompile/fixture';
  assert.equal(Buffer.from(evidence.fuzz_failures[name], 'base64').toString(), 'controlled fuzz input');
  assert.equal(fs.existsSync(path.join(f.root, name)), true);
  assert.equal(evidence.commands[2].exit, 0);
});


test('existing Go on PATH is preferred and absent installations stay absent', async t => {
  const f = await fixture(t);
  const found = await executionEnvironment(f.config.env, []);
  assert.equal(found.resolution.source, 'PATH');
  const absent = await executionEnvironment({ PATH: '/nonexistent' }, []);
  assert.equal(absent.resolution.source, 'unavailable');
  assert.equal(absent.env.PATH, '/nonexistent');
});

test('existing native Go outside PATH is discovered without provisioning', async t => {
  const f = await fixture(t);
  const version = `go version go1.26.8 ${process.platform}/${{x64:'amd64',arm64:'arm64'}[process.arch] || process.arch}`;
  fs.writeFileSync(path.join(f.bin, 'go'), `#!${process.execPath}\nconsole.log(${JSON.stringify(version)});`, {mode:0o755});
  const prepared = await executionEnvironment({PATH:'/nonexistent'}, [f.bin]);
  assert.equal(prepared.resolution.source, 'preexisting installation');
  assert.equal(prepared.resolution.probes[0].exit, 0);
  assert.equal(prepared.env.PATH.split(path.delimiter)[0], f.bin);
});

test('credential reset preserves configuration and allows fixture CLI helper', async t => {
  const f = await fixture(t);
  const prepared = await executionEnvironment({...process.env,
    GIT_CONFIG_COUNT:'2', GIT_CONFIG_KEY_0:'credential.helper',
    GIT_CONFIG_VALUE_0:'!echo INTERFERING >&2; exit 1',
    GIT_CONFIG_KEY_1:'test.preserved', GIT_CONFIG_VALUE_1:'retained'}, []);
  // credential fill requires stdin; use a shell pipeline with fixed synthetic fixture input.
  const filled = await runCommand(['sh','-c',
    `printf 'protocol=https\\nhost=fixture.invalid\\n\\n' | git -c 'credential.helper=!f() { echo username=fixture; echo password=disposable; }; f' credential fill`],
    {cwd:f.root,env:prepared.env});
  assert.equal(filled.exit, 0);
  assert.match(filled.stdout, /username=fixture/);
  assert.doesNotMatch(filled.stderr, /INTERFERING/);
  const kept = await runCommand(['git','config','--get','test.preserved'],{cwd:f.root,env:prepared.env});
  assert.equal(kept.stdout.trim(), 'retained');
});
