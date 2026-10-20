/* 页面内配置与管理锁的回归检查。需要先在 4611 起 mock、在 4620 起 server.mjs --public。
   node _dev/check-admin.mjs
   会临时改 local/config.json，跑完（含出错）恢复原样。 */
import { readFileSync, writeFileSync } from "node:fs";
const BASE = process.env.GAP_BASE || "http://127.0.0.1:4620";
const CFG = new URL("../local/config.json", import.meta.url);
const original = readFileSync(CFG, "utf8");
/* 泄漏扫描与"跑完应与开跑前一致"都用配置里原本那把 Key，别写死常量——
   写死的话，配置文件里若是另一把 Key，这套用例自己就会把自己的断言跑失败。 */
const SECRET = (JSON.parse(original).upstream || {}).key || "";
const PW = "keclass7";
const results = [];
let leaks = [];

function ok(name, cond, detail) { results.push({ name, pass: !!cond, detail: detail === undefined ? "" : String(detail).slice(0, 150) }) }
function scan(where, text) { if (String(text || "").includes(SECRET)) leaks.push(where) }
/* 每次运行换一个来源 IP：解锁限流是按来源分桶的，固定来源会让"上一次跑"打满的额度
   污染"这一次跑"（表现为一上来就 429，后面全 403）。 */
const RUN_IP = "198.51.100." + (1 + Math.floor(Math.random() * 250));
async function hit(path, opts = {}) {
  const headers = Object.assign({
    "x-forwarded-for": opts.local ? "" : "203.0.113.9",
    "cf-connecting-ip": opts.local ? "" : (opts.ip || RUN_IP),
  }, opts.headers || {});
  const res = await fetch(BASE + path, { method: opts.method || "GET", headers, body: opts.body, redirect: "manual" });
  const text = await res.text();
  scan(path + " body", text);
  for (const [k, v] of res.headers.entries()) scan(path + " header " + k, v);
  let j = null; try { j = JSON.parse(text) } catch { }
  return { status: res.status, text, j, res };
}
function restore() { writeFileSync(CFG, original, { mode: 0o600 }) }

async function main() {
  const POST = (p, body, extra = {}) => hit(p, Object.assign({ method: "POST", headers: Object.assign({ "content-type": "application/json" }, extra.headers || {}), body: JSON.stringify(body) }, extra));

  /* 1. 读配置永远脱敏 */
  const g = await hit("/api/settings");
  ok("访客能读到脱敏配置", g.status === 200 && g.j && g.j.ok === true, g.status);
  ok("GET /api/settings 不含明文 Key", !g.text.includes(SECRET) && /\*\*\*\w{4}/.test(g.j.keyHint), g.j.keyHint);
  ok("出厂态：未设管理密码", g.j.lockSet === false, "lockSet=" + g.j.lockSet);

  /* 2. 没设密码时：公网写被拒、本机可写 */
  const wOut = await POST("/api/settings", { model: "hijacked" });
  ok("未设密码时公网写配置被拒", wOut.status === 403 && /本机/.test(wOut.j.error), wOut.status + " " + (wOut.j.error || "").slice(0, 40));
  const wIn = await POST("/api/settings", { model: "mock-model-name" }, { local: true });
  ok("未设密码时本机能写配置", wIn.status === 200 && wIn.j.ok === true, wIn.status + " " + (wIn.j.error || ""));

  /* 3. 本机设密码 */
  const setp = await POST("/api/admin/lock", { current: "", next: PW }, { local: true });
  ok("本机设好管理密码并拿到令牌", setp.status === 200 && setp.j.ok && setp.j.token && setp.j.token.length >= 32, setp.status);
  const TOKEN = setp.j.token || "";
  const g2 = await hit("/api/settings", { local: true });
  ok("设完之后 lockSet 变 true", g2.j.lockSet === true);

  /* 4. 上锁后：没令牌一律写不动 */
  const noTok = await POST("/api/settings", { model: "hijacked" });
  ok("上锁后无令牌写配置被拒", noTok.status === 403 && /解锁/.test(noTok.j.error), noTok.status);
  const localNoTok = await POST("/api/settings", { model: "hijacked" }, { local: true });
  ok("上锁后连本机回环也要令牌（否则课堂上的锁形同虚设）", localNoTok.status === 403, localNoTok.status);
  const badTok = await POST("/api/settings", { model: "hijacked" }, { headers: { "x-admin-token": "deadbeef" } });
  ok("伪造令牌被拒", badTok.status === 403, badTok.status);

  /* 5. 解锁 */
  const badPw = await POST("/api/admin/unlock", { password: "wrong" });
  ok("错密码解锁被拒", badPw.status === 401, badPw.status);
  const goodPw = await POST("/api/admin/unlock", { password: PW });
  ok("对密码解锁拿到令牌", goodPw.status === 200 && goodPw.j.token, goodPw.status);
  const T2 = goodPw.j.token;
  const withTok = await POST("/api/settings", { model: "mock-model-name" }, { headers: { "x-admin-token": T2 } });
  ok("带令牌能写配置", withTok.status === 200 && withTok.j.ok === true, withTok.status + " " + (withTok.j.error || ""));

  /* 6. Key：留空保持、clearKey 才清空 */
  const keep = await POST("/api/settings", { key: "", model: "mock-model-name" }, { local: true, headers: { "x-admin-token": T2 } });
  ok("Key 留空＝保持原值不变", keep.status === 200 && keep.j.hasKey === true, keep.status + " " + keep.j.keyHint);
  const setNew = await POST("/api/settings", { key: "sk-ANOTHER-KEY-9999" }, { local: true, headers: { "x-admin-token": T2 } });
  ok("填了新 Key 会覆盖", setNew.status === 200 && /\*\*\d{4}/.test(setNew.j.keyHint), setNew.j.keyHint);
  const cleared = await POST("/api/settings", { clearKey: true }, { local: true, headers: { "x-admin-token": T2 } });
  ok("独立 clearKey 能清空", cleared.status === 200 && cleared.j.hasKey === false, cleared.j.keyHint);
  await POST("/api/settings", { key: SECRET }, { local: true, headers: { "x-admin-token": T2 } });

  /* 7. baseUrl 校验 */
  const httpPub = await POST("/api/settings", { baseUrl: "http://api.example.com/v1" }, { local: true, headers: { "x-admin-token": T2 } });
  ok("公网地址禁用 http", httpPub.status === 400 && /https/.test(httpPub.j.error), (httpPub.j.error || "").slice(0, 46));
  const meta = await POST("/api/settings", { baseUrl: "http://169.254.169.254/latest" }, { local: true, headers: { "x-admin-token": T2 } });
  ok("拦掉云元数据地址", meta.status === 400 && /元数据/.test(meta.j.error), (meta.j.error || "").slice(0, 46));
  const localHttp = await POST("/api/settings", { baseUrl: "http://127.0.0.1:4611/v1" }, { local: true, headers: { "x-admin-token": T2 } });
  ok("本机 http 端点放行", localHttp.status === 200, localHttp.status + " " + (localHttp.j.error || ""));
  const junk = await POST("/api/settings", { baseUrl: "file:///c:/windows" }, { local: true, headers: { "x-admin-token": T2 } });
  ok("非 http/https 被拒", junk.status === 400, junk.status);

  /* 8. 测试接口按未保存的表单值试 */
  const t = await POST("/api/settings/test", { baseUrl: "http://127.0.0.1:4611/v1", model: "mock" }, { local: true, headers: { "x-admin-token": T2 } });
  ok("测试接口能拿通", t.status === 200 && t.j.ok === true && t.j.reply, t.status + " " + JSON.stringify(t.j).slice(0, 60));
  const tOut = await POST("/api/settings/test", {});
  ok("没令牌也不让人白烧测试额度", tOut.status === 403, tOut.status);

  /* 9. 改/取消密码都必须先验原密码 */
  const chgBad = await POST("/api/admin/lock", { current: "nope", next: "1234" }, { headers: { "x-admin-token": T2 } });
  ok("改密码不验原密码被拒（有令牌也不行）", chgBad.status === 401, chgBad.status);
  const cancelBad = await POST("/api/admin/lock", { current: "nope", next: "" }, { headers: { "x-admin-token": T2 } });
  ok("取消密码也要验原密码", cancelBad.status === 401, cancelBad.status);
  const shortPw = await POST("/api/admin/lock", { current: PW, next: "12" });
  ok("过短密码被拒", shortPw.status === 400, shortPw.status);

  /* 10. 取消密码：旧令牌同时失效，回到"只有本机能写" */
  const cancel = await POST("/api/admin/lock", { current: PW, next: "" });
  ok("验过原密码能取消密码", cancel.status === 200 && cancel.j.ok === true, cancel.status);
  const afterCancel = await hit("/api/settings", { local: true });
  ok("取消后 lockSet 回到 false", afterCancel.j.lockSet === false);
  const oldTokDead = await POST("/api/settings", { model: "mock-model-name" }, { headers: { "x-admin-token": T2 } });
  ok("取消密码后旧令牌立刻作废", oldTokDead.status === 403, oldTokDead.status);
  const localAgain = await POST("/api/settings", { model: "mock-model-name" }, { local: true });
  ok("取消后本机仍可写（回到出厂口径）", localAgain.status === 200, localAgain.status);

  /* 11. 解锁限流放最后：它会全局关 30 秒 */
  let throttled = 0;
  for (let i = 0; i < 7; i++) {
    const r = await POST("/api/admin/unlock", { password: "guess" + i });
    if (r.status === 429) { throttled = i + 1; break }
  }
  ok("解锁尝试被限流（防课堂上一遍遍试）", throttled > 0, "第 " + throttled + " 次开始 429");

  /* 12. 配置最终没被改坏 */
  const now = readFileSync(CFG, "utf8");
  ok("跑完 config.json 与开跑前一致", JSON.parse(now).upstream.key === JSON.parse(original).upstream.key
    && !JSON.parse(now).lock, "key/lock 已核对");

  console.log("\n============ 配置与锁 ============");
  let fail = 0;
  for (const r of results) { if (!r.pass) fail++; console.log((r.pass ? " PASS  " : "*FAIL*  ") + r.name + (r.detail ? "   [" + r.detail + "]" : "")) }
  console.log("\n密钥泄漏点：", leaks.length ? leaks : "无");
  console.log("合计 " + results.length + " 项，失败 " + fail + " 项");
  restore();
  process.exit(fail || leaks.length ? 1 : 0);
}
main().catch(e => { restore(); console.log("脚本自己出错了：" + e.message + "\n（config.json 已恢复）"); process.exit(2) });
