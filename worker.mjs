/* 中间那一步 · Cloudflare Worker
   静态页面走 Workers Assets；/api/* 由这个 Worker 转发到 OpenAI 兼容上游。
   Key 只从 Cloudflare Secret（UPSTREAM_API_KEY）读取，绝不下发给浏览器。 */

const DEFAULT_BASE = "https://api.deepseek.com";
const DEFAULT_MODEL = "deepseek-chat";
const MAX_BODY = 256 * 1024;
const ROLES = new Set(["system", "user", "assistant"]);

function json(obj, status = 200, extra = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: Object.assign({
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
    }, extra),
  });
}

function cfg(env) {
  return {
    baseUrl: String(env.UPSTREAM_BASE_URL || DEFAULT_BASE).trim().replace(/\/+$/, ""),
    model: String(env.UPSTREAM_MODEL || DEFAULT_MODEL).trim(),
    key: String(env.UPSTREAM_API_KEY || "").trim(),
  };
}

function hostOf(baseUrl) {
  try { return new URL(baseUrl).host; } catch { return ""; }
}

function keyHint(key) {
  return key ? "已配置（Cloudflare Secret，页面不可读取）" : "";
}

function configured(c) {
  return !!(c.baseUrl && c.model && c.key);
}

function sanitize(raw) {
  let body;
  try { body = JSON.parse(raw || "{}"); } catch {
    throw Object.assign(new Error("请求体不是合法 JSON"), { code: 400 });
  }
  if (!Array.isArray(body.messages) || !body.messages.length)
    throw Object.assign(new Error("messages 不能为空"), { code: 400 });
  if (body.messages.length > 40)
    throw Object.assign(new Error("一次最多 40 条消息"), { code: 400 });
  const messages = [];
  for (const m of body.messages) {
    if (!m || !ROLES.has(m.role) || typeof m.content !== "string")
      throw Object.assign(new Error("消息格式不对"), { code: 400 });
    if (m.content.length > 24000)
      throw Object.assign(new Error("单条消息过长"), { code: 400 });
    messages.push({ role: m.role, content: m.content });
  }
  const t = Number(body.temperature);
  const mt = Number(body.max_tokens);
  return {
    messages,
    stream: body.stream === true,
    temperature: Number.isFinite(t) ? Math.min(2, Math.max(0, t)) : 0.7,
    max_tokens: Number.isFinite(mt) ? Math.min(4000, Math.max(200, mt)) : 1800,
  };
}

async function readBody(request) {
  const len = Number(request.headers.get("content-length") || 0);
  if (len > MAX_BODY) throw Object.assign(new Error("请求体过大"), { code: 413 });
  const text = await request.text();
  if (text.length > MAX_BODY) throw Object.assign(new Error("请求体过大"), { code: 413 });
  return text;
}

async function callUpstream(c, payload, signal) {
  const url = /\/chat\/completions$/.test(c.baseUrl)
    ? c.baseUrl
    : c.baseUrl + "/chat/completions";
  const headers = { "Content-Type": "application/json" };
  if (c.key) headers.Authorization = "Bearer " + c.key;
  let upstream;
  try {
    upstream = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify(payload),
      signal,
    });
  } catch (e) {
    const name = e && e.name === "AbortError" ? "请求已取消" : (e && e.name) || "网络错误";
    throw Object.assign(new Error("连不上上游：" + name), { code: 502 });
  }
  return upstream;
}

function statusPayload(env) {
  const c = cfg(env);
  return {
    ok: true,
    publicMode: true,
    local: false,
    managed: true,
    lockSet: false,
    writable: false,
    modelConfigured: configured(c),
    model: c.model || "",
    baseUrlHost: hostOf(c.baseUrl),
    keyHint: keyHint(c.key) || "未配置",
    used: { global: 0, session: 0, resetIn: 0 },
    limit: { per10min: 0, dayMax: 0 },
  };
}

function settingsPayload(env) {
  const c = cfg(env);
  return {
    ok: true,
    managed: true,
    baseUrl: c.baseUrl,
    model: c.model,
    keyHint: keyHint(c.key),
    hasKey: !!c.key,
    lockSet: false,
    local: false,
    publicMode: true,
    writable: false,
    rate: { per10min: 0, dayMax: 0 },
    note: "配置由 Cloudflare Workers 托管：Key 在 Secret 中，页面只读。",
  };
}

async function handleChat(request, env) {
  const c = cfg(env);
  if (!configured(c)) {
    return json({
      ok: false,
      error: "Cloudflare Worker 还没配置上游：请设置 UPSTREAM_API_KEY，并检查 UPSTREAM_BASE_URL / UPSTREAM_MODEL。",
    }, 500);
  }
  let payload;
  try {
    payload = sanitize(await readBody(request));
  } catch (e) {
    return json({ ok: false, error: e.message }, e.code || 400);
  }
  const t0 = Date.now();
  let upstream;
  try {
    upstream = await callUpstream(c, Object.assign({ model: c.model }, payload), request.signal);
  } catch (e) {
    return json({ ok: false, error: e.message }, e.code || 502);
  }

  const ct = upstream.headers.get("content-type") || "";
  if (!upstream.ok) {
    let text = "";
    try { text = (await upstream.text()).slice(0, 600); } catch { /* 忽略 */ }
    const hint = upstream.status === 401 || upstream.status === 403
      ? "（上游拒绝了这枚 Key，检查 Cloudflare Secret 是否填对、是否属于这家服务商）"
      : upstream.status === 404 ? "（UPSTREAM_BASE_URL 或 UPSTREAM_MODEL 不对）"
      : upstream.status === 429 ? "（上游限流，等一会儿再问）" : "";
    return json({ ok: false, error: "上游 HTTP " + upstream.status + " " + hint, raw: text }, 502);
  }

  if (payload.stream && ct.includes("event-stream")) {
    return new Response(upstream.body, {
      status: 200,
      headers: {
        "Content-Type": "text/event-stream; charset=utf-8",
        "Cache-Control": "no-store",
        "X-Accel-Buffering": "no",
      },
    });
  }

  const j = await upstream.json().catch(() => null);
  if (!j) return json({ ok: false, error: "上游回了非 JSON 内容" }, 502);
  const ch = j.choices && j.choices[0];
  const msg = (ch && (ch.message || ch.delta)) || {};
  const text = msg.content || (ch && ch.text) || "";
  if (!text && msg.reasoning_content) {
    return json({
      ok: false,
      error: "模型只回了思考过程、没有正文。把 max_tokens 调到 2000 以上，或换非推理模型（deepseek-chat、qwen-max 这一档）。",
    }, 502);
  }
  return json({ ok: true, content: text, ms: Date.now() - t0 });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      if (request.method === "OPTIONS" && path.startsWith("/api/")) {
        return new Response(null, { status: 204, headers: { Allow: "GET,POST,OPTIONS" } });
      }
      if (path === "/api/status" && request.method === "GET") {
        return json(statusPayload(env));
      }
      if (path === "/api/settings" && request.method === "GET") {
        return json(settingsPayload(env));
      }
      if (path === "/api/settings" && request.method === "POST") {
        return json({
          ok: false,
          error: "配置由 Cloudflare Workers 托管。要换 Key / 模型，请用 wrangler secret 或 Cloudflare 控制台修改 Worker 变量。",
        }, 403);
      }
      if (path === "/api/chat" && request.method === "POST") {
        return handleChat(request, env);
      }
      if (path.startsWith("/api/")) {
        return json({ ok: false, error: "没有这个接口" }, 404);
      }
      if (env.ASSETS) return env.ASSETS.fetch(request);
      return new Response("Not found", { status: 404 });
    } catch (e) {
      return json({ ok: false, error: "Worker 出错：" + (e && e.message ? e.message : String(e)) }, 500);
    }
  },
};
