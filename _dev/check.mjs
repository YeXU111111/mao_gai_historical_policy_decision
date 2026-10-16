/* 部署链路端到端检查（没有访问码那一版）。需要先在 4611 起 mock、在 4620 起 server.mjs --public。
   node _dev/check.mjs
   只对 http://127.0.0.1:4620 说话，用 x-forwarded-for 模拟"从公网进来"。 */
const BASE = process.env.GAP_BASE || "http://127.0.0.1:4620";
const SECRET = "SECRET-DO-NOT-LEAK-1234";
const results = [];
let leaks = [];

function ok(name, cond, detail) {
  results.push({ name, pass: !!cond, detail: detail === undefined ? "" : String(detail).slice(0, 160) });
}
function scan(where, text) {
  const t = String(text || "");
  if (t.includes(SECRET)) leaks.push(where);
  if (/Bearer\s+SECRET/i.test(t)) leaks.push(where + "(header)");
}
async function hit(path, opts = {}) {
  const headers = Object.assign({ "x-forwarded-for": opts.local ? "" : "203.0.113.9" }, opts.headers || {});
  const res = await fetch(BASE + path, { method: opts.method || "GET", headers, body: opts.body, redirect: "manual" });
  const text = await res.text();
  scan((opts.local ? "local " : "out ") + path + " body", text);
  for (const [k, v] of res.headers.entries()) scan(path + " header " + k, v);
  let j = null; try { j = JSON.parse(text) } catch { }
  return { status: res.status, text, j, res };
}
const CHAT = JSON.stringify({
  model: "IGNORED-BY-CLIENT",
  messages: [{ role: "system", content: "你是判卷与推演者" }, { role: "user", content: "【本次作答】\n分田地\n\n【第 1 次判定" }],
  stream: false,
});
/* 必须是纯 hex：ensureSid 只认 /^[a-f0-9]{16,64}$/，不认的就每次现发一个新会话，限流根本测不出来 */
const SID = Math.random().toString(16).slice(2, 10) + Date.now().toString(16);
const ask = (extra = {}) => hit("/api/chat", Object.assign({ method: "POST", headers: { "content-type": "application/json", cookie: "gapsid=" + SID }, body: CHAT }, extra));
const POST_unlock = (password, headers = {}) => hit("/api/admin/unlock",
  { method: "POST", headers: Object.assign({ "content-type": "application/json" }, headers), body: JSON.stringify({ password }) });

async function main() {
  /* 1. 页面：本机与公网都直接给（没有门禁了） */
  const local = await hit("/", { local: true });
  ok("本机拿到页面", local.status === 200 && local.text.includes("中间那一步"), "HTTP " + local.status);
  const out = await hit("/");
  ok("公网也直接拿到页面（不再有验码跳转）", out.status === 200 && out.text.includes("中间那一步"), "HTTP " + out.status);
  ok("不再发门票 cookie", !/gappass/.test(out.res.headers.get("set-cookie") || ""), out.res.headers.get("set-cookie") || "（无）");
  const fresh = await hit("/api/chat", { method: "POST", headers: { "content-type": "application/json" }, body: CHAT });
  ok("没带会话 cookie 时会被发一个（限流才有得算）", /gapsid=[a-f0-9]{16,}/.test(fresh.res.headers.get("set-cookie") || ""), (fresh.res.headers.get("set-cookie") || "（无）").slice(0, 40));
  ok("带着合法会话 cookie 时不重复发", !/gapsid=/.test((await ask()).res.headers.get("set-cookie") || ""));

  /* 2. 代理转发 */
  const c = await ask();
  ok("公网访客能问 /api/chat", c.status === 200 && c.j && c.j.ok === true && c.j.content.length > 0, c.status + " " + (c.j.error || "").slice(0, 60));
  ok("客户端自报的 model 被忽略、由服务端定", !/IGNORED-BY-CLIENT/.test(c.text));
  const st = await hit("/api/chat", { method: "POST", headers: { "content-type": "application/json", cookie: "gapsid=" + SID }, body: JSON.stringify({ messages: [{ role: "system", content: "你是判卷与推演者" }, { role: "user", content: "【本次作答】\n分田地" }], stream: true }) });
  ok("流式 SSE 原样透传", st.status === 200 && /text\/event-stream/.test(st.res.headers.get("content-type") || "") && st.text.includes("data:") && st.text.includes("[DONE]"), st.res.headers.get("content-type"));

  /* 3. 越权文件一律读不到 */
  for (const p of ["/local/config.json", "/../local/config.json", "/%2e%2e/local/config.json", "/local/usage.json", "/server.mjs", "/deploy/public-launch.mjs", "/_dev/mock.js", "/access.html"]) {
    const r = await hit(p);
    ok("拒绝 " + p, r.status === 404, r.status);
  }

  /* 4. 状态与配置只回脱敏信息 */
  const pubStatus = await hit("/api/status");
  ok("状态接口不下发明文 Key", pubStatus.status === 200 && !pubStatus.text.includes(SECRET) && /\*\*\*\w{4}/.test(pubStatus.j.keyHint), pubStatus.j.keyHint);
  const pubSet = await hit("/api/settings");
  ok("配置接口不下发明文 Key", pubSet.status === 200 && !pubSet.text.includes(SECRET) && /\*\*\*\w{4}/.test(pubSet.j.keyHint), pubSet.j.keyHint);
  ok("状态里已无门禁/门票字段", !/"gate"|"needPass"|visitCode/i.test(pubStatus.text + pubSet.text));

  /* 5. 请求体校验 */
  const empty = await hit("/api/chat", { method: "POST", headers: { "content-type": "application/json", cookie: "gapsid=" + SID }, body: JSON.stringify({ messages: [] }) });
  ok("空 messages 被拒", empty.status === 400, empty.status + " " + empty.text.slice(0, 40));
  const junk = await hit("/api/chat", { method: "POST", headers: { "content-type": "application/json", cookie: "gapsid=" + SID }, body: "not json" });
  ok("非 JSON 被拒", junk.status === 400, junk.status);
  const role = await hit("/api/chat", { method: "POST", headers: { "content-type": "application/json", cookie: "gapsid=" + SID }, body: JSON.stringify({ messages: [{ role: "tool", content: "x" }] }) });
  ok("非白名单 role 被拒", role.status === 400, role.status);

  /* 6. 限流：按服务端实际限额来打 */
  const lim = (await (await fetch(BASE + "/api/status")).json()).limit || {};
  const cap = Math.min(80, Math.max(2, (Number(lim.per10min) || 40) + 2));
  let got429 = 0, codes = [];
  for (let i = 0; i < cap; i++) {
    const r = await ask();
    codes.push(r.status);
    if (r.status === 429) { got429 = i + 1; break; }
  }
  ok("每会话 10 分钟限流生效", got429 > 0, "限额 " + (lim.per10min || 40) + "，第 " + got429 + " 次被限，末段 " + codes.slice(-3).join(","));

  /* 7. 上游挂了要给人话 */
  const fs = await import("node:fs");
  const cfgPath = new URL("../local/config.json", import.meta.url);
  const keep = JSON.parse(fs.readFileSync(cfgPath, "utf8"));
  fs.writeFileSync(cfgPath, JSON.stringify(Object.assign(JSON.parse(JSON.stringify(keep)), { upstream: Object.assign({}, keep.upstream, { baseUrl: "http://127.0.0.1:4999/v1" }) }), null, 2));
  await new Promise(r => setTimeout(r, 150));
  const dead = await hit("/api/chat", { method: "POST", headers: { "content-type": "application/json", cookie: "gapsid=" + SID + "x" }, body: CHAT });
  ok("上游不可达时回 502 与人话", dead.status === 502 && /连不上上游/.test(dead.text), dead.status + " " + dead.text.slice(0, 70));
  fs.writeFileSync(cfgPath, JSON.stringify(keep, null, 2));

  /* 8. Fix4：rate 写 0 必须真的是不限（以前被悄悄改回 40/400） */
  const writeCfg=o=>fs.writeFileSync(cfgPath,JSON.stringify(o,null,2),{mode:0o600});
  writeCfg(Object.assign({},keep,{rate:{per10min:0,dayMax:0}}));
  await new Promise(r=>setTimeout(r,150));
  const lim0=(await (await fetch(BASE+"/api/status")).json()).limit;
  ok("rate 写 0 时状态接口如实报 0",lim0.per10min===0&&lim0.dayMax===0,JSON.stringify(lim0));
  let any429=0;
  for(let i=0;i<12;i++){const r=await ask();if(r.status===429)any429++}
  ok("0＝不限 真的不限（连问 12 次没被拦）",any429===0,"被拦 "+any429+" 次");
  writeCfg(keep);

  /* 9. Fix3：解锁限流按来源分桶——一个人刷错密码不能把老师也关在门外 */
  await POST_unlock("guess",{"cf-connecting-ip":"1.1.1.1"});
  await POST_unlock("guess",{"cf-connecting-ip":"1.1.1.1"});
  await POST_unlock("guess",{"cf-connecting-ip":"1.1.1.1"});
  await POST_unlock("guess",{"cf-connecting-ip":"1.1.1.1"});
  await POST_unlock("guess",{"cf-connecting-ip":"1.1.1.1"});
  const flooded=await POST_unlock("guess",{"cf-connecting-ip":"1.1.1.1"});
  const other=await POST_unlock("wrong-once",{"cf-connecting-ip":"9.9.9.9"});
  ok("同一来源连错 5 次后被限流",flooded.status===429,flooded.status);
  ok("别的来源不受牵连（还能正常尝）",other.status!==429,"来源 9.9.9.9 拿到 "+other.status);

  /* 10. Fix5：页面保存不能丢掉手写的未知字段 */
  writeCfg(Object.assign({},keep,{teacherNote:"这行是我手写的"}));
  const saveNoLoss=await hit("/api/settings",{method:"POST",local:true,headers:{"content-type":"application/json"},body:JSON.stringify({model:"mock-model-name"})});
  const afterSave=JSON.parse(fs.readFileSync(cfgPath,"utf8"));
  ok("保存配置后手写字段还在",saveNoLoss.status===200&&afterSave.teacherNote==="这行是我手写的",JSON.stringify(afterSave.teacherNote||"(丢了)"));
  writeCfg(keep);

  /* 11. Fix2：客户端流式中途断开，服务端不能崩、后面照常服务 */
  const ac=new AbortController();
  let gotFirst=false;
  try{
    const r=await fetch(BASE+"/api/chat",{method:"POST",signal:ac.signal,
      headers:{"content-type":"application/json",cookie:"gapsid="+SID},
      body:JSON.stringify({messages:[{role:"system",content:"你是判卷与推演者"},{role:"user",content:"【本次作答】\n分田地"}],stream:true})});
    const rd=r.body.getReader();await rd.read();gotFirst=true;ac.abort();
  }catch(_){}
  await new Promise(r=>setTimeout(r,400));
  /* 用一个全新会话探活：SID 在前面第 6 段已经被打到限流上限了 */
  const alive=await hit("/api/chat",{method:"POST",headers:{"content-type":"application/json",cookie:"gapsid="+Math.random().toString(16).slice(2,10)+Date.now().toString(16)},body:CHAT});
  ok("流式中途断开后服务还活着",gotFirst&&alive.status===200,"首块收到 "+gotFirst+"，之后请求 "+alive.status);

  console.log("\n================ 部署链路 ================");
  let fail = 0;
  for (const r of results) { if (!r.pass) fail++; console.log((r.pass ? " PASS  " : "*FAIL*  ") + r.name + (r.detail ? "   [" + r.detail + "]" : "")) }
  console.log("\n密钥泄漏点：", leaks.length ? leaks : "无（全部响应正文与响应头都扫过）");
  console.log("合计 " + results.length + " 项，失败 " + fail + " 项");
  process.exit(fail || leaks.length ? 1 : 0);
}
main().catch(e => { console.log("脚本自己出错了：" + e.message); process.exit(2) });
