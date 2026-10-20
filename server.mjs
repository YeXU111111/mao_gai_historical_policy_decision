/* 中间那一步 · 本机后端代理
   只做两件事：托管页面、把 /api/chat 转发给上游大模型（Key 只活在这台电脑上）。
   没有访问码那一道：链接本身即入口，靠限流与"配置写入要锁"兜。

   用法：
     node server.mjs                      仅本机：http://127.0.0.1:4620/
     node server.mjs 4620 --public        对外跑：开限流（仍只听 127.0.0.1，配合隧道用）
     node server.mjs 4620 --public --bind 0.0.0.0

   上游配置写在 local/config.json（本文件不读环境变量，避免和 hist_sim 那套混起来）：
     { "upstream": { "baseUrl": "https://…/v1", "model": "qwen-max", "key": "sk-…" },
       "rate": { "per10min": 40, "dayMax": 400 }, "lock": { "salt": "…", "hash": "…" } }
   每次请求现读，改完不用重启。lock 段没有就是"未设管理密码"。 */

import http from "node:http";
import crypto from "node:crypto";
import {readFileSync, writeFileSync, mkdirSync, existsSync, renameSync} from "node:fs";
import {fileURLToPath} from "node:url";
import {dirname, join, normalize} from "node:path";

const ROOT=dirname(fileURLToPath(import.meta.url));
const LOCAL=join(ROOT,"local");
const CFG=join(LOCAL,"config.json");
const USAGE=join(LOCAL,"usage.json");

const argv=process.argv.slice(2);
let PORT=4620, PUBLIC=false, BIND="127.0.0.1";
for(let i=0;i<argv.length;i++){
  const a=argv[i];
  if(a==="--public"){PUBLIC=true;BIND="0.0.0.0"}
  else if(a==="--bind"){BIND=argv[++i]||BIND}
  else if(/^\d+$/.test(a))PORT=Number(a);
}
const SID_COOKIE="gapsid";
const DAY_MS=24*3600*1000, WINDOW_MS=10*60*1000;
const MAX_BODY=256*1024;
const ROLES=new Set(["system","user","assistant"]);

/* ---------------- 配置 ---------------- */
function readJson(p,fallback){try{return JSON.parse(readFileSync(p,"utf8"))}catch(_){return fallback}}
function writeJson(p,obj){
  mkdirSync(dirname(p),{recursive:true});
  const tmp=p+".tmp";
  writeFileSync(tmp,JSON.stringify(obj,null,2),{mode:0o600});
  renameSync(tmp,p);
}
/* 限流数字：0 是"不限"，不是"没填"。没填（缺字段/非数字）才回落到默认值。 */
function num(v,fallback){const n=Number(v);return Number.isFinite(n)&&n>=0?n:fallback}
function cfg(){
  const c=readJson(CFG,{});
  const u=c.upstream||{}, r=c.rate||{};
  return{
    baseUrl:String(u.baseUrl||"").trim().replace(/\/+$/,""),
    model:String(u.model||"").trim(),
    key:String(u.key||"").trim(),
    per10min:num(r.per10min,40),
    dayMax:num(r.dayMax,400),
  };
}
/* ---------------- 管理锁：改配置要有令牌 ---------------- */
/* 出厂不设密码，方便老师第一次本机配好；但"没锁"绝不等于"谁都能改"——
   没锁时只有本机回环写得动，公网来的写一律拒绝，必须先在这台电脑上设一道密码。
   锁一旦设了，本机回环也要令牌：这里的锁是防课堂上别人动手改，回环豁免会让它形同虚设。 */
const TOKEN_TTL=2*3600*1000;
const tokens=new Map();
const UNLOCK_WINDOW=30*1000, UNLOCK_MAX=5;
const unlockHits=new Map();
/* 来源地址：隧道场景下 cf-connecting-ip 由 Cloudflare 强制覆写、伪造不了，优先信它。
   但桶键里一定要带上 socket 的真实对端地址——万一有人不走隧道直连这台 0.0.0.0，
   那样他改个头就能把自己的配额刷新掉，等于没限流。 */
function clientIp(req){
  const cf=String(req.headers["cf-connecting-ip"]||"").trim();
  if(cf)return "cf:"+cf;
  const xff=String(req.headers["x-forwarded-for"]||"").split(",")[0].trim();
  if(xff)return "xff:"+xff;
  const xr=String(req.headers["x-real-ip"]||"").trim();
  if(xr)return "xr:"+xr;
  return "sock:"+(req.socket.remoteAddress||"?");
}
function throttleUnlock(req){
  const now=Date.now();
  const key=clientIp(req)+"|"+(req.socket.remoteAddress||"?");
  const hits=(unlockHits.get(key)||[]).filter(t=>now-t<UNLOCK_WINDOW);
  if(hits.length>=UNLOCK_MAX){
    unlockHits.set(key,hits);
    return Math.ceil((UNLOCK_WINDOW-(now-hits[0]))/1000);
  }
  hits.push(now);unlockHits.set(key,hits);
  if(unlockHits.size>2000){
    for(const [k,v] of unlockHits){const f=v.filter(t=>now-t<UNLOCK_WINDOW);if(!f.length)unlockHits.delete(k);else unlockHits.set(k,f)}
  }
  return 0;
}
function hashPw(pw,salt){return crypto.scryptSync(String(pw),Buffer.from(salt,"hex"),64).toString("hex")}
function lockInfo(){const c=readJson(CFG,{});return c.lock&&typeof c.lock.hash==="string"?c.lock:null}
function checkPw(pw){
  const l=lockInfo();
  if(!l)return false;
  const got=Buffer.from(hashPw(pw,l.salt)),want=Buffer.from(l.hash);
  return got.length===want.length&&crypto.timingSafeEqual(got,want);
}
function issueToken(){
  const t=crypto.randomBytes(24).toString("hex");
  tokens.set(t,Date.now()+TOKEN_TTL);
  return t;
}
function validToken(t){
  if(!t)return false;
  const exp=tokens.get(String(t));
  if(!exp)return false;
  if(Date.now()>exp){tokens.delete(String(t));return false}
  return true;
}
function canWrite(req){
  const l=lockInfo();
  if(!l)return isLoopback(req);
  return validToken(req.headers["x-admin-token"]);
}

/* ---------------- baseUrl 校验 ---------------- */
/* 注意别把 ^…$ 套在整串选择组外面：那样 "127." 会变成"必须正好等于 127."，
   127.0.0.1 反而被判成公网。本机/内网一律用前缀匹配。 */
function isPrivateHost(host){
  const h=String(host||"").toLowerCase().replace(/^\[|\]$/g,"");
  return h==="localhost"||h.endsWith(".local")||h==="::1"||h==="0.0.0.0"
    ||/^127\./.test(h)||/^10\./.test(h)||/^192\.168\./.test(h)
    ||/^172\.(1[6-9]|2\d|3[01])\./.test(h)||/^::ffff:127\./.test(h);
}
function checkBaseUrl(u){
  const s=String(u||"").trim().replace(/\/+$/,"");
  if(!s)return"Base URL 不能为空。";
  let parsed;
  try{parsed=new URL(s)}catch(_){return"Base URL 不是合法地址（要带 https:// 开头）。"}
  if(parsed.protocol!=="https:"&&parsed.protocol!=="http:")return"只允许 http / https，不接受 "+parsed.protocol;
  const host=parsed.hostname;
  if(/^169\.254\./i.test(host)||host==="metadata.google.internal"||/^fe80:/i.test(host))
    return"这个地址指向云主机的元数据服务，不允许。";
  if(parsed.protocol==="http:"&&!isPrivateHost(host))
    return"公网地址必须用 https，否则 Key 会在网络上裸奔。本机/内网端点（127.、10.、192.168.、172.16-31.、*.local）才允许 http。";
  if(parsed.username||parsed.password)return"Base URL 里不要带账号密码，Key 请填在专门的格子里。";
  return"";
}
/* 脱敏：明文 Key 永不下发 */
function keyHint(k){
  const s=String(k||"");
  if(!s)return"";
  return"已配置（***"+s.slice(-4)+"，共 "+s.length+" 位）";
}

/* ---------------- 用量与限流 ---------------- */
function usage(){
  const u=readJson(USAGE,null);
  const today=new Date().toISOString().slice(0,10);
  if(!u||u.day!==today)return{day:today,global:0,sessions:{}};
  return u;
}
let usageMem=usage(), usageFlush=null;
function bump(sid){
  const today=new Date().toISOString().slice(0,10);
  if(usageMem.day!==today)usageMem={day:today,global:0,sessions:{}};
  usageMem.global++;
  const now=Date.now();
  const s=usageMem.sessions[sid]||(usageMem.sessions[sid]={t:now,n:0});
  if(now-s.t>WINDOW_MS){s.t=now;s.n=0}
  s.n++;
  /* 过期会话顺手清掉：公网挂一天被爬，这张表不能只增不减 */
  const keys=Object.keys(usageMem.sessions);
  if(keys.length>200){
    for(const k of keys){const e=usageMem.sessions[k];if(!e||now-e.t>WINDOW_MS)delete usageMem.sessions[k]}
    const still=Object.keys(usageMem.sessions);
    if(still.length>2000)for(const k of still.sort((a,b)=>usageMem.sessions[a].t-usageMem.sessions[b].t).slice(0,still.length-2000))delete usageMem.sessions[k];
  }
  if(!usageFlush)usageFlush=setTimeout(()=>{usageFlush=null;try{writeJson(USAGE,usageMem)}catch(_){}},1500).unref?.();
  return{global:usageMem.global,session:s.n,resetIn:Math.max(0,WINDOW_MS-(now-s.t))};
}
function peek(sid){
  const today=new Date().toISOString().slice(0,10);
  if(usageMem.day!==today)return{global:0,session:0,resetIn:0};
  const s=usageMem.sessions[sid];
  const now=Date.now();
  const live=s&&(now-s.t<=WINDOW_MS)?s.n:0;
  return{global:usageMem.global,session:live,resetIn:s?Math.max(0,WINDOW_MS-(now-s.t)):0};
}

/* ---------------- HTTP 小工具 ---------------- */
function cookies(req){
  const out={};
  for(const part of String(req.headers.cookie||"").split(";")){
    const i=part.indexOf("=");
    if(i>0)out[part.slice(0,i).trim()]=decodeURIComponent(part.slice(i+1).trim());
  }
  return out;
}
function viaProxy(req){return !!(req.headers["x-forwarded-for"]||req.headers["x-real-ip"]||req.headers["cf-connecting-ip"])}
function isLoopback(req){
  if(!viaProxy(req)){
    const a=req.socket.remoteAddress||"";
    return a==="127.0.0.1"||a==="::1"||a==="::ffff:127.0.0.1"||a.startsWith("127.");
  }
  return false;
}
function secure(req){
  if(String(req.headers["x-forwarded-proto"]||"").split(",")[0].trim()==="https")return true;
  return String(req.headers["cf-visitor-json"]||"").includes('"https"');
}
function send(res,code,body,headers){
  const h=Object.assign({"Content-Type":"text/plain; charset=utf-8"},headers||{});
  res.writeHead(code,h);
  res.end(body);
}
function json(res,code,obj,headers){send(res,code,JSON.stringify(obj),Object.assign({"Content-Type":"application/json; charset=utf-8","Cache-Control":"no-store"},headers||{}))}
function readBody(req){
  return new Promise((resolve,reject)=>{
    let n=0,chunks=[];
    req.on("data",c=>{n+=c.length;if(n>MAX_BODY){reject(new Error("请求体过大"));req.destroy()}else chunks.push(c)});
    req.on("end",()=>resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error",reject);
  });
}
function sidCookie(req,sid){
  const parts=[SID_COOKIE+"="+sid,"Path=/","HttpOnly","SameSite=Lax","Max-Age="+DAY_MS/1000];
  if(secure(req))parts.push("Secure");
  return parts.join("; ");
}
function ensureSid(req,res){
  const ck=cookies(req);
  if(ck[SID_COOKIE]&&/^[a-f0-9]{16,64}$/.test(ck[SID_COOKIE]))return ck[SID_COOKIE];
  const s=crypto.randomBytes(12).toString("hex");
  const h=res.getHeader("Set-Cookie")||[];
  res.setHeader("Set-Cookie",[].concat(h,sidCookie(req,s)));
  return s;
}
/* ---------------- 静态文件（白名单，local/ 与源码一律不发） ---------------- */
const MIME={".html":"text/html;charset=utf-8",".js":"text/javascript;charset=utf-8",".css":"text/css;charset=utf-8"};
const PUBLIC_FILES=new Set(["/index.html","/favicon.ico"]);
function serveStatic(req,res,rel){
  const clean=normalize("/"+rel.replace(/\0/g,"")).replace(/\\/g,"/");
  const abs=join(ROOT,clean);
  if(!abs.startsWith(ROOT)||!PUBLIC_FILES.has(clean))return send(res,404,"not found");
  if(!existsSync(abs))return send(res,404,"not found");
  try{
    const buf=readFileSync(abs);
    res.writeHead(200,{"Content-Type":(MIME[clean.slice(clean.lastIndexOf("."))]||"text/plain;charset=utf-8"),
      "Cache-Control":"no-cache","X-Content-Type-Options":"nosniff"});
    res.end(buf);
  }catch(e){send(res,500,"读取失败："+e.message)}
}

/* ---------------- 上游转发 ---------------- */
async function callUpstream(payload,signal){
  const c=cfg();
  if(!c.baseUrl||!c.model)throw Object.assign(new Error("上游没配好：local/config.json 里 baseUrl 或 model 是空的。"),{code:500});
  if(!c.key&&!isPrivateHost((()=>{try{return new URL(c.baseUrl).hostname}catch(_){return""}})()))
    throw Object.assign(new Error("上游没填 Key。"),{code:500});
  const url=/\/chat\/completions$/.test(c.baseUrl)?c.baseUrl:c.baseUrl+"/chat/completions";
  const headers={"Content-Type":"application/json"};
  if(c.key)headers.Authorization="Bearer "+c.key;
  const signals=[AbortSignal.timeout(Math.max(30000,Number(payload.max_tokens)*80))];
  if(signal)signals.push(signal);
  let res;
  try{
    res=await fetch(url,{method:"POST",headers,body:JSON.stringify(payload),signal:AbortSignal.any(signals)});
  }catch(e){
    if(e&&e.name==="AbortError")throw Object.assign(new Error("已取消（浏览器那头已经断开，不再占着这条上游连接）。"),{code:499});
    const name=e&&e.name==="TimeoutError"?"请求超时":(e&&e.cause&&e.cause.code)||e.name||"网络错误";
    const issuer=e&&e.cause&&e.cause.reason&&/self[- ]signed|certificate/i.test(String(e.cause.reason))?
      "（对端证书是自签的，多半被本机杀毒软件拦了 TLS——hist_sim 那台机器上卡巴斯基就这么干过）":"";
    throw Object.assign(new Error("连不上上游："+name+issuer),{code:502});
  }
  return{res,c};
}
function sanitize(raw){
  let body;
  try{body=JSON.parse(raw||"{}")}catch(_){throw Object.assign(new Error("请求体不是合法 JSON"),{code:400})}
  if(!Array.isArray(body.messages)||!body.messages.length)throw Object.assign(new Error("messages 不能为空"),{code:400});
  if(body.messages.length>40)throw Object.assign(new Error("一次最多 40 条消息"),{code:400});
  const messages=[];
  for(const m of body.messages){
    if(!m||!ROLES.has(m.role)||typeof m.content!=="string")throw Object.assign(new Error("消息格式不对"),{code:400});
    if(m.content.length>24000)throw Object.assign(new Error("单条消息过长"),{code:400});
    messages.push({role:m.role,content:m.content});
  }
  const t=Number(body.temperature);
  const mt=Number(body.max_tokens);
  return{messages,stream:body.stream===true,
    temperature:Number.isFinite(t)?Math.min(2,Math.max(0,t)):0.7,
    max_tokens:Number.isFinite(mt)?Math.min(4000,Math.max(200,mt)):1800};
}

/* ---------------- 路由 ---------------- */
const server=http.createServer(async(req,res)=>{
  const path=(req.url||"/").split("?")[0];
  const c=cfg();
  try{
    if(req.method==="OPTIONS"){res.writeHead(204,{"Allow":"GET,POST,OPTIONS"});return res.end()}

    if(path==="/api/status"){
      return json(res,200,{ok:true,publicMode:PUBLIC,local:isLoopback(req),
        lockSet:!!lockInfo(),writable:canWrite(req),
        modelConfigured:!!(c.baseUrl&&c.model&&(c.key||isPrivateHost((()=>{try{return new URL(c.baseUrl).hostname}catch(_){return""}})()))),
        model:c.model||"",
        baseUrlHost:(()=>{try{return new URL(c.baseUrl||"http://x").host}catch(_){return""}})(),
        keyHint:keyHint(c.key)||"未配置",
        used:peek(cookies(req)[SID_COOKIE]||"anon"),
        limit:{per10min:c.per10min,dayMax:c.dayMax}});
    }

    /* ---------- 页面内配置：读永远脱敏，写必须有锁 ---------- */
    if(path==="/api/settings"&&req.method==="GET"){
      const raw=readJson(CFG,{});
      return json(res,200,{ok:true,baseUrl:c.baseUrl,model:c.model,
        keyHint:keyHint(c.key),hasKey:!!c.key,
        lockSet:!!lockInfo(),local:isLoopback(req),publicMode:PUBLIC,
        writable:canWrite(req),
        rate:{per10min:c.per10min,dayMax:c.dayMax},
        note:"明文 Key 不会下发；留空表示保持原 Key，要清空请用「清除已存 Key」。"});
    }
    if(path==="/api/settings"&&req.method==="POST"){
      if(!canWrite(req))return json(res,403,{ok:false,error:lockInfo()
        ?"没解锁改不了配置。在下面的「管理密码」里输一次密码换 2 小时的令牌。"
        :"现在还没设管理密码，为防公网页面对任何人开放写入，只有这台电脑上（本机浏览器）能改。请先在本机设一个密码。"});
      let b={};try{b=JSON.parse(await readBody(req))}catch(e){return json(res,400,{ok:false,error:"请求体不是合法 JSON"})}
      const raw=readJson(CFG,{});
      const u=Object.assign({},raw.upstream||{});
      /* 先展开原配置再覆盖，老师手写在 config.json 里的额外字段不会被一次保存抹掉 */
      const next=Object.assign({},raw,{upstream:u,rate:Object.assign({},raw.rate||{})});
      if(b.baseUrl!==undefined){
        const err=checkBaseUrl(b.baseUrl);
        if(err)return json(res,400,{ok:false,error:"Base URL："+err});
        u.baseUrl=String(b.baseUrl).trim().replace(/\/+$/,"");
      }
      if(b.model!==undefined)u.model=String(b.model).trim();
      /* 留空 = 保持原 Key；清空只走独立的 clearKey */
      if(b.key!==undefined&&String(b.key).trim()!=="")u.key=String(b.key).trim();
      if(b.clearKey===true)u.key="";
      if(b.rate){
        const p=Number(b.rate.per10min),d=Number(b.rate.dayMax);
        if(Number.isFinite(p))next.rate.per10min=Math.max(0,Math.min(1000,Math.round(p)));
        if(Number.isFinite(d))next.rate.dayMax=Math.max(0,Math.min(100000,Math.round(d)));
      }
      writeJson(CFG,next);
      const c2=cfg();
      return json(res,200,{ok:true,baseUrl:c2.baseUrl,model:c2.model,keyHint:keyHint(c2.key),
        hasKey:!!c2.key,rate:{per10min:c2.per10min,dayMax:c2.dayMax},
        note:"已写入 local/config.json，下一次请求就生效，不用重启。"});
    }
    if(path==="/api/admin/unlock"&&req.method==="POST"){
      const wait=throttleUnlock(req);
      if(wait>0)return json(res,429,{ok:false,error:"解锁尝试太频繁，"+wait+" 秒后再试。"},{"Retry-After":String(wait)});
      let b={};try{b=JSON.parse(await readBody(req))}catch(e){return json(res,400,{ok:false,error:"请求体不是合法 JSON"})}
      if(!lockInfo())return json(res,200,{ok:true,token:"",note:"还没设管理密码，本机直接就能改。"});
      if(!checkPw(b.password))return json(res,401,{ok:false,error:"管理密码不对。"});
      return json(res,200,{ok:true,token:issueToken(),ttlMinutes:120});
    }
    if(path==="/api/admin/lock"&&req.method==="POST"){
      /* 设/改/取消都必须先验原密码——不设"留空即取消"这种暗门 */
      let b={};try{b=JSON.parse(await readBody(req))}catch(e){return json(res,400,{ok:false,error:"请求体不是合法 JSON"})}
      const l=lockInfo();
      if(l&&!checkPw(b.current))return json(res,401,{ok:false,error:"要先验原密码。"+(validToken(req.headers["x-admin-token"])?"":"（原密码输对过一次才能改，忘了就删 local/config.json 里的 lock 字段后重启服务）")});
      if(!l&&!isLoopback(req))return json(res,403,{ok:false,error:"第一次设密码请在这台电脑自己的浏览器里做。"});
      const next=readJson(CFG,{});
      const pw=String(b.next||"");
      if(pw){
        if(pw.length<4)return json(res,400,{ok:false,error:"密码至少 4 位。课堂上的锁不用长，能挡住手滑和起哄就行。"});
        const salt=crypto.randomBytes(16).toString("hex");
        next.lock={salt,hash:hashPw(pw,salt),setAt:Date.now()};
        writeJson(CFG,next);
        const t=issueToken();
        return json(res,200,{ok:true,token:t,ttlMinutes:120,note:"密码已设。之前发出去的公网链接不受影响；这台电脑之外的浏览器要改配置得先解锁。"});
      }
      if(!l)return json(res,400,{ok:false,error:"现在本来就没有密码。"});
      delete next.lock;
      writeJson(CFG,next);
      tokens.clear();
      return json(res,200,{ok:true,token:"",note:"密码已取消，所有已发出的解锁令牌同时失效；改配置回到「只有本机能写」。"});
    }
    if(path==="/api/settings/test"&&req.method==="POST"){
      if(!canWrite(req))return json(res,403,{ok:false,error:"测试会真的发一次请求，也要先解锁。"});
      let b={};try{b=JSON.parse(await readBody(req))}catch(e){return json(res,400,{ok:false,error:"请求体不是合法 JSON"})}
      if(b.baseUrl!==undefined){const err=checkBaseUrl(b.baseUrl);if(err)return json(res,400,{ok:false,error:"Base URL："+err})}
      const saved=cfg();
      const use={
        baseUrl:b.baseUrl!==undefined?String(b.baseUrl).trim().replace(/\/+$/,""):saved.baseUrl,
        model:b.model!==undefined&&String(b.model).trim()?String(b.model).trim():saved.model,
        key:String(b.key||"").trim()||saved.key,
      };
      if(!use.baseUrl||!use.model)return json(res,400,{ok:false,error:"Base URL 或模型名是空的。"});
      const t0=Date.now();
      try{
        const url=/\/chat\/completions$/.test(use.baseUrl)?use.baseUrl:use.baseUrl+"/chat/completions";
        const headers={"Content-Type":"application/json"};
        if(use.key)headers.Authorization="Bearer "+use.key;
        const r=await fetch(url,{method:"POST",headers,signal:AbortSignal.timeout(30000),
          body:JSON.stringify({model:use.model,messages:[{role:"user",content:"只回一个字：通"}],max_tokens:16,stream:false})});
        const txt=await r.text();
        if(!r.ok)return json(res,200,{ok:false,status:r.status,error:"上游 HTTP "+r.status+"："+txt.slice(0,300)});
        let j=null;try{j=JSON.parse(txt)}catch(_){return json(res,200,{ok:false,error:"上游回的不是 JSON，Base URL 可能填到了错误的接口上："+txt.slice(0,200)})}
        const content=(j.choices&&j.choices[0]&&(j.choices[0].message&&j.choices[0].message.content||j.choices[0].text))||"";
        return json(res,200,{ok:true,ms:Date.now()-t0,reply:String(content).slice(0,40)});
      }catch(e){
        return json(res,200,{ok:false,error:"发不出去："+((e&&e.cause&&e.cause.code)||e.name||"")+" "+(e&&e.message?e.message:"")});
      }
    }

    if(path==="/api/chat"&&req.method==="POST"){
      const sid=ensureSid(req,res);
      const u=bump(sid);
      if(c.per10min>0&&u.session>c.per10min)
        return json(res,429,{ok:false,error:"这个会话 10 分钟内问了 "+u.session+" 次，先歇 "+Math.ceil(u.resetIn/1000)+" 秒。"},
          {"Retry-After":String(Math.ceil(u.resetIn/1000))});
      if(c.dayMax>0&&u.global>c.dayMax)
        return json(res,429,{ok:false,error:"今天全场已经用了 "+u.global+" 次，到封顶了。明天自动恢复，或让老师改 local/config.json 里 rate.dayMax。"});
      let payload;
      try{payload=sanitize(await readBody(req))}
      catch(e){return json(res,e.code||400,{ok:false,error:e.message})}
      const t0=Date.now();
      /* 浏览器那头一断（刷新、关页、切题），立刻取消上游请求：
         流式生成是边产边推的，掐了连接通常也就止住了后面那几十秒的计费。
         注意：abort() 会把被取消请求的 rejection 抛出去，必须自己吞掉——
         之前没吞，客户端一刷新就能把整个服务进程打挂。 */
      const ac=new AbortController();
      let upstreamDone=false;
      res.on("close",()=>{
        if(res.writableEnded||upstreamDone)return;
        try{ac.abort()}catch(_){}
      });
      let up;
      try{up=await callUpstream(Object.assign({model:cfg().model},payload),ac.signal)}
      catch(e){upstreamDone=true;if(e.code===499)return;return json(res,e.code||502,{ok:false,error:e.message})}
      upstreamDone=true;
      const{res:ures}=up;
      const ct=ures.headers.get("content-type")||"";
      if(!ures.ok){
        let txt="";try{txt=(await ures.text()).slice(0,600)}catch(_){}
        if(ac.signal.aborted)return;
        const hint=ures.status===401||ures.status===403?"（服务商拒了这把 Key：检查是否填对、是否属于这家、额度是否用完）"
          :ures.status===404?"（baseUrl 或 model 不对，baseUrl 一般填到 /v1 为止）"
          :ures.status===429?"（上游限流，等一会儿再问）":"";
        return json(res,502,{ok:false,error:"上游 HTTP "+ures.status+" "+hint,raw:txt});
      }
      if(payload.stream&&ct.includes("event-stream")){
        res.writeHead(200,{"Content-Type":"text/event-stream; charset=utf-8","Cache-Control":"no-store",
          "X-Accel-Buffering":"no","Connection":"keep-alive"});
        try{
          for await(const chunk of ures.body){
            if(ac.signal.aborted||res.writableEnded)break;
            if(!res.write(chunk))await new Promise(r=>res.once("drain",r));
          }
        }catch(_){/* 客户端断开或上游提前收尾，下面统一 end */}
        finally{try{ures.body&&ures.body.cancel&&ures.body.cancel()}catch(_){}res.end()}
        return;
      }
      const j=await ures.json().catch(()=>null);
      if(ac.signal.aborted)return;
      if(!j)return json(res,502,{ok:false,error:"上游回了非 JSON 内容"});
      const ch=j.choices&&j.choices[0];
      const msg=ch&&(ch.message||ch.delta)||{};
      const text=msg.content||(ch&&ch.text)||"";
      if(!text&&msg.reasoning_content)
        return json(res,502,{ok:false,error:"模型只回了思考过程、没有正文（推理模型常见）。把 max_tokens 调大到 2000 以上，或换非推理模型（qwen-max、deepseek-chat 这一档）。"});
      return json(res,200,{ok:true,content:text,ms:Date.now()-t0});
    }

    if(path.startsWith("/api/"))return json(res,404,{ok:false,error:"没有这个接口"});
    if(req.method!=="GET")return send(res,405,"只支持 GET");
    return serveStatic(req,res,path==="/"?"/index.html":path);
  }catch(e){
    /* 单次请求出错不能把整个服务带走——公网下那等于全班一起断 */
    try{json(res,500,{ok:false,error:"服务端出错："+(e&&e.message?e.message:String(e))})}catch(_){res.destroy()}
  }
});

/* 课堂服务不能因为一次客户端断开就整体挂掉：被取消的请求、断掉的流都会冒出
   没人接的 rejection，这里统一吞掉并记一行，进程继续服务其他人。 */
process.on("unhandledRejection",(e)=>{
  console.log("[已吞掉一个未处理的 rejection] "+(e&&e.message?e.message:String(e)));
});

server.on("error",e=>{
  if(e.code==="EADDRINUSE"){
    console.log("\n[起不来] 端口 "+PORT+" 已经被别的程序占了。");
    console.log("        注意：Windows 允许 127.0.0.1:"+PORT+" 和 0.0.0.0:"+PORT+" 并存，浏览器可能先打到那个，页面一片空白。");
    console.log("        查一下：netstat -ano | findstr :"+PORT);
    console.log("        换端口：node server.mjs "+(PORT+1)+(PUBLIC?" --public":"")+"\n");
  }else console.log("\n[起不来] "+e.message+"\n");
  process.exit(1);
});
server.listen(PORT,BIND,()=>{
  mkdirSync(LOCAL,{recursive:true});
  const c=cfg();
  console.log("中间那一步 · 服务已起");
  console.log("  地址      http://"+(BIND==="0.0.0.0"?"127.0.0.1":BIND)+":"+PORT+"/");
  console.log("  监听      "+BIND+"   模式 "+(PUBLIC?"对外（开限流）":"仅本机"));
  console.log("  上游      "+(c.baseUrl?c.baseUrl+"  模型 "+c.model:"未配置（打开 local/config.json 填 baseUrl / model / key，或在页面「设置」里改）"));
  console.log("  Key       "+(c.key?"已配置，只留在本机，不会发给浏览器":"未配置"));
  console.log("  管理锁    "+(lockInfo()?"已设密码：改配置要先解锁（忘了就删 config.json 的 lock 段重启）":"未设密码：只有这台电脑自己的浏览器能改配置"));
  console.log("  限流      每会话 "+c.per10min+" 次/10 分钟，全场 "+c.dayMax+" 次/天（local/config.json 的 rate 可调，0 是不限）");
  console.log("\n  配置文件 local/config.json 每次请求现读，改完不用重启。");
});
