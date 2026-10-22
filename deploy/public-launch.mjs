/* 双击上线：起本机服务 → 起 Cloudflare 隧道 → 拼出"点开就能用"的分享链接并复制到剪贴板。
   关掉这个窗口，公网网址立刻断。
   隧道断了不再整体收摊：本机服务继续跑，脚本自己重连并打印新网址。
   全过程（含 cloudflared 的原话）记在 local/launch.log，那份文件只在本机、不会被网页读到。
   用法：双击 deploy/启动公网.bat，或在终端里 node deploy/public-launch.mjs

   与 hist_sim 那套的差别：这里没有后台页面，也没有访问码——链接本身就是入口；
   模型与 Key 存在 local/config.json，可以在页面「设置」里改，也可以直接编辑那个文件。 */

import { spawn } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { appendFile, mkdir, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const PORT = Number(process.env.GAP_PORT || 4620);
const LOCAL_APP = `http://127.0.0.1:${PORT}`;
const LOCAL_DIR = join(ROOT, 'local');
const CFG = join(LOCAL_DIR, 'config.json');
const LOG_FILE = join(LOCAL_DIR, 'launch.log');
const LOG_MAX_BYTES = 512 * 1000;
const CF_CANDIDATES = [
  'cloudflared',
  'C:\\Program Files (x86)\\cloudflared\\cloudflared.exe',
  'C:\\Program Files\\cloudflared\\cloudflared.exe',
];
const FIRST_TRY = 6;
const RECONNECT_TRY = 8;

let server = null;
let tunnel = null;
let closing = false;

/* ---------------- 日志 ---------------- */
async function initLog() {
  await mkdir(LOCAL_DIR, { recursive: true });
  const stamp = new Date().toLocaleString('zh-CN', { hour12: false });
  let size = 0;
  try { size = (await stat(LOG_FILE)).size; } catch { /* 第一次没有文件 */ }
  if (size > LOG_MAX_BYTES) { await writeFile(LOG_FILE, '==== 日志超过 512KB，旧的已清掉 ====\n', { mode: 0o600 }); size = 0; }
  await appendFile(LOG_FILE, (size ? '\n' : '') + '==== 启动 ' + stamp + '  端口 ' + PORT + ' ====\n', { mode: 0o600 });
}
let logReady = initLog().catch(() => {});

/* 只写文件（cloudflared 的啰嗦输出走这条，不刷屏） */
function note(text) {
  const clean = String(text).replace(/\s+$/, '');
  if (!clean) return;
  logReady = logReady.then(() => appendFile(LOG_FILE, new Date().toLocaleTimeString('zh-CN', { hour12: false }) + '  ' + clean + '\n', { mode: 0o600 })).catch(() => {});
}
function log(...args) {
  console.log(...args);
  note(args.map((a) => (typeof a === 'string' ? a : String(a))).join(' '));
}

/* die() 必须真的掐断流程：否则隧道没起来也会打印一条 "undefined" 的假链接 */
const STOP = Symbol('stop');
function stop(msg, hint) {
  log('\n[停] ' + msg + (hint ? '\n      ' + hint : '') + '\n');
  cleanup(1);
}
function die(msg, hint) {
  stop(msg, hint);
  throw STOP;
}
function cleanup(code) {
  if (closing) return;
  closing = true;
  try { if (tunnel) tunnel.kill('SIGTERM'); } catch { /* 忽略 */ }
  try { if (server) server.kill('SIGTERM'); } catch { /* 忽略 */ }
  setTimeout(() => {
    Promise.race([logReady, sleep(600)]).then(() => process.exit(code || 0), () => process.exit(code || 0));
  }, 200);
}
/* 事件回调里冒出来的异常 main().catch() 接不住；不兜住会带着两个没人管的子进程一起消失 */
process.on('uncaughtException', (error) => {
  stop('启动脚本遇到意外：' + (error && error.message ? error.message : String(error)), '子进程一并收掉，不留孤儿服务。原因已记入 local/launch.log。');
});

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function fetchJson(url, opts) {
  const res = await fetch(url, opts);
  const data = await res.json().catch(() => ({}));
  return { status: res.status, data };
}
async function waitApp(timeoutMs) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const { data } = await fetchJson(LOCAL_APP + '/api/status', { headers: { origin: LOCAL_APP } });
      if (data && data.ok) return data;
    } catch { /* 还没起来 */ }
    await sleep(300);
  }
  return null;
}

/* ---------------- 配置：读—改—写，保留老师已填的其它字段 ---------------- */
function readCfg() {
  try { return JSON.parse(readFileSync(CFG, 'utf8')); } catch { return null; }
}
function writeCfg(obj) {
  return writeFile(CFG, JSON.stringify(obj, null, 2), { mode: 0o600 });
}
async function ensureCfg() {
  let c = readCfg();
  if (!c) {
    let seed = { upstream: { baseUrl: 'https://dashscope.aliyuncs.com/compatible-mode/v1', model: 'qwen-max', key: '' }, rate: { per10min: 0, dayMax: 0 } };
    try { seed = JSON.parse(readFileSync(join(LOCAL_DIR, 'config.example.json'), 'utf8')); } catch { /* 没有示例就用内置 */ }
    await writeCfg(seed);
    log('           local/config.json 不存在，已按模板建好一份。');
    c = seed;
  }
  return c;
}

/* ---------------- 隧道 ---------------- */
async function spawnTunnel() {
  for (const bin of CF_CANDIDATES) {
    let child = null;
    try {
      child = spawn(bin, ['tunnel', '--url', 'http://127.0.0.1:' + PORT, '--no-autoupdate'], { cwd: ROOT, stdio: ['ignore', 'ignore', 'pipe'], windowsHide: true });
      child.on('error', () => { child = null; });
      let lineBuf = '';
      child.stderr.on('data', (chunk) => {
        lineBuf += chunk.toString('utf8');
        let cut;
        while ((cut = lineBuf.indexOf('\n')) >= 0) {
          const line = lineBuf.slice(0, cut).trim();
          lineBuf = lineBuf.slice(cut + 1);
          if (line) note('  [cloudflared] ' + line);
        }
      });
      await sleep(600);
      if (child && (child.killed || child.exitCode)) child = null;
      if (child) return child;
    } catch { child = null; }
  }
  return null;
}
/* cloudflared 自己调的注册接口地址也在输出里，必须排掉 api. 前缀 */
function waitForUrl(child, ms) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(ms / 1000 + ' 秒内没拿到隧道网址')), ms);
    let buf = '';
    const onData = (chunk) => {
      buf += chunk.toString('utf8');
      const hits = String(buf).match(/https:\/\/[a-z0-9-]+\.trycloudflare\.com/gi) || [];
      const real = hits.find((u) => !/^https:\/\/api\./i.test(u));
      if (real) { clearTimeout(timer); resolve(real); }
    };
    child.stderr.on('data', onData);
    if (child.stdout) child.stdout.on('data', onData);
    child.on('exit', (c) => { clearTimeout(timer); reject(new Error('隧道进程退出，代码 ' + c)); });
  });
}
const waitForExit = (child) => new Promise((resolve) => {
  child.on('exit', (code) => resolve(code));
  child.on('error', () => resolve('进程出错'));
});
function copyToClipboard(text) {
  const clip = spawn('clip', { stdio: 'pipe' });
  clip.on('error', () => {});
  clip.stdin.end(text);
}

function printLink(url, again) {
  const link = url + '/';
  log(again ? '\n[重连成功] 新网址：' : '\n  发给别人的链接（点开直接玩，什么都不用输）：');
  log('    ' + link);
  if (again) log('  注意：网址变了，之前发出去的链接已经失效，要重新发一次。');
  copyToClipboard(link);
  log(again ? '  （新链接已复制到剪贴板）' : '  （链接已复制到剪贴板，直接粘贴到群里）');
  note((again ? '重连后网址：' : '对外网址：') + url);
}

async function keepTunnelAlive() {
  while (!closing) {
    const code0 = await waitForExit(tunnel);
    if (closing) return;
    if (server && (server.exitCode !== null || server.killed)) {
      stop('本机服务和隧道一起退出了（隧道退出代码 ' + code0 + '）', '看 local/launch.log 里的最后几行找原因。');
      return;
    }
    log('\n[断] 隧道退出（代码 ' + code0 + '）。本机服务照常能用，正在自动重连...');
    let revived = false;
    for (let i = 1; i <= RECONNECT_TRY && !revived && !closing; i++) {
      log('  第 ' + i + '/' + RECONNECT_TRY + ' 次重连...');
      await sleep(2000);
      const child = await spawnTunnel();
      if (!child) { log('    没找到 cloudflared，稍后再试'); continue; }
      try {
        const fresh = await waitForUrl(child, 45000);
        tunnel = child;
        printLink(fresh, true);
        revived = true;
      } catch (error) {
        log('    没成：' + (error && error.message ? error.message : String(error)));
        try { child.kill('SIGTERM'); } catch { /* 忽略 */ }
      }
    }
    if (!revived && !closing) {
      stop('隧道连续 ' + RECONNECT_TRY + ' 次都没能重连', '原因记在 local/launch.log。本机页面 http://127.0.0.1:' + PORT + '/ 仍然能用；同网段的设备也可以直接访问 http://本机IP:' + PORT + '/。');
      return;
    }
  }
}

async function main() {
  log('=== 中间那一步 · 一键公网 ===\n');

  let status = await waitApp(900);
  if (!status) {
    log('[1/4] 启动本机服务（公网模式，只听 127.0.0.1，由隧道对外）...');
    server = spawn(process.execPath, [join(ROOT, 'server.mjs'), String(PORT), '--public', '--bind', '127.0.0.1'], {
      cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true,
    });
    for (const stream of [server.stdout, server.stderr]) {
      if (!stream) continue;
      let lineBuf = '';
      stream.on('data', (chunk) => {
        lineBuf += chunk.toString('utf8');
        let cut;
        while ((cut = lineBuf.indexOf('\n')) >= 0) {
          const line = lineBuf.slice(0, cut).trim();
          lineBuf = lineBuf.slice(cut + 1);
          if (line) note('  [server] ' + line);
        }
      });
    }
    server.on('exit', (code) => { if (!closing) stop('本机服务退出了（代码 ' + code + '）', '多半是端口被占或 server.mjs 报错，看 local/launch.log 最后几行。'); });
    status = await waitApp(6000);
    if (!status) die('本机服务起不来', '先在终端跑 node server.mjs ' + PORT + ' --public --bind 127.0.0.1 看看报什么。');
  } else {
    log('[1/4] 检测到本机服务已在跑，直接复用它。');
    if (!status.publicMode) {
      log('       提醒：那个实例是"仅本机"模式，没开限流。课堂上几十个人共用一个出口，');
      log('       建议先把它关掉、由本脚本以 --public 重新起（限流按会话算，全班不会互相挤占）。');
    }
  }

  log('[2/4] 检查配置...');
  await ensureCfg();
  if (!status.modelConfigured) {
    log('\n[还差一步] 模型没配好（local/config.json 里的 baseUrl / model / key）。');
    log('           现在分享出去，别人能打开页面但会看到"这台电脑的服务还没配 Key"。');
    log('           在页面的「设置」里填，或直接编辑那个文件——不用重启，每次请求现读。');
  }
  if (!status.lockSet) {
    log('           还没设管理密码：现在只有这台电脑自己的浏览器能改配置，别人只读得到脱敏信息。');
  }

  log('[3/4] 打开 Cloudflare 隧道（第一次会弹防火墙提示，点允许即可）...');
  /* trycloudflare 的注册接口会抽：慢的时候一次要 4 秒以上，经常超过 cloudflared 自己的等待上限，
     表现就是"隧道进程退出，代码 1"，同一台机器再试往往就通了。拿不到网址就重试，六次不行直接退出。 */
  let url = '';
  let lastErr = '';
  for (let attempt = 1; attempt <= FIRST_TRY && !url; attempt++) {
    if (attempt > 1) {
      log('  第 ' + (attempt - 1) + ' 次没成功（' + lastErr + '），2 秒后重试...');
      await sleep(2000);
    }
    const child = await spawnTunnel();
    if (!child) { lastErr = '没找到 cloudflared（先装一次：winget install --id Cloudflare.cloudflared -e）'; continue; }
    tunnel = child;
    try {
      url = await waitForUrl(child, 45000);
    } catch (error) {
      lastErr = error && error.message ? error.message : String(error);
      try { child.kill('SIGTERM'); } catch { /* 忽略 */ }
      tunnel = null;
    }
  }
  if (!url) {
    die('隧道起不来：' + lastErr, '连试 ' + FIRST_TRY + ' 次都没拿到网址。这是 Cloudflare 那边的注册接口不通/太慢，不是本机服务的问题——过几分钟再双击一次；本机页面 http://127.0.0.1:' + PORT + '/ 和同网段访问不受影响。');
  }

  log('[4/4] 上线了。\n');
  printLink(url, false);
  log('');
  log('  你自己在本机开：' + LOCAL_APP + '/（本机免验码）');
  log('  想让网址立刻失效：关掉这个窗口。想挡住乱改配置的人：在页面「设置」里设一道管理密码。');
  log('  隧道断了会自动重连（本机服务不断），但重连后网址会变——日志在 local/launch.log。');
  log('\n—— 这个窗口请一直开着。Ctrl+C 或关窗口 = 网址立刻断。——');

  process.on('SIGINT', () => { log('\n正在收摊...'); cleanup(0); });
  process.on('SIGTERM', () => cleanup(0));
  await keepTunnelAlive();
}

/* 双击运行时窗口只在出错时才一闪而过：兜住任何意外，把原因留在屏幕上 */
main().catch((error) => {
  if (error === STOP) return;
  stop('启动脚本自己出错了：' + (error && error.message ? error.message : String(error)), '把这行文字或 local/launch.log 的最后几行发给授课老师排查。');
});
