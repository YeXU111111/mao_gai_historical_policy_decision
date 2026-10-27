/* 纯函数回归。直接从 index.html 里按标记抽取，不引第三方库、不改交付形态。
   这些函数是整个工具最绕的部分（题面泄漏自检、去重、判卷标记、刷新恢复），
   改动它们之后跑一遍这个，比手点一局可靠得多。
   用法：node _dev/unit.mjs */
import { readFileSync } from "node:fs";
import vm from "node:vm";

const html = readFileSync(new URL("../index.html", import.meta.url), "utf8");
const script = html.slice(html.indexOf("<script>"), html.lastIndexOf("</script>"));

/* 按顺序拼出纯函数区；顺序必须与源文件一致（A 定义 norm/read，F 用到它们） */
const ORDER = ["A", "B", "C", "D", "E", "F"];
let src = "";
for (const tag of ORDER) {
  const s = script.indexOf(`/* PURE-START-${tag} */`);
  const e = script.indexOf(`/* PURE-END-${tag} */`);
  if (s < 0 || e < 0) throw new Error(`找不到纯函数区 ${tag} 的标记`);
  src += script.slice(s, e) + "\n";
}
src += `
globalThis.__api={esc,norm,md,parseFields,leakWords,checkLeak,isRepeat,parseVerdict,stripMarkText,
  yearOf,inEra,eraById,ERAS,normalise,blank,PHASES};
`;

const ctx = {
  console,
  document: { querySelector: () => null },
  localStorage: { getItem: () => null, setItem() {}, removeItem() {} },
  matchMedia: () => ({ matches: false }),
  setTimeout, clearTimeout, setInterval, clearInterval,
};
vm.createContext(ctx);
new vm.Script(src, { filename: "pure-blocks.js" }).runInContext(ctx);
const A = ctx.__api;

const results = [];
function ok(name, cond, detail) {
  results.push({ name, pass: !!cond, detail: detail === undefined ? "" : String(detail).slice(0, 120) });
}
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

/* ---------- parseFields：字段不能互相吞并（这条曾出过真 bug） ---------- */
const Q = [
  "【时期】", "1927年秋收起义后，湘赣边界。",
  "【前提】", "攻城受挫，部队减员过半。",
  "【结果】", "到1929年，红军发展到万余人。",
  "【答案】", "\"工农武装割据\"",
  "【要点】", "转向农村｜三者结合｜依靠农民",
  "【岔路】", "再攻大城市。",
].join("\n");
const f = A.parseFields(Q);
ok("parseFields 认出 6 个字段", same(Object.keys(f), ["时期", "前提", "结果", "答案", "要点", "岔路"]), Object.keys(f).join(","));
ok("parseFields 结果不吞并下一个标记", f["结果"] === "到1929年，红军发展到万余人。", f["结果"]);
ok("parseFields 答案只含答案", f["答案"] === "\"工农武装割据\"", f["答案"]);
ok("parseFields 空输入返回空对象", same(A.parseFields(""), {}));
ok("parseFields 无标记返回空对象", same(A.parseFields("随便一段话"), {}));
const fCrlf = A.parseFields(Q.replace(/\n/g, "\r\n"));
ok("parseFields 认 CRLF 行尾", fCrlf["前提"] === "攻城受挫，部队减员过半。" && Object.keys(fCrlf).length === 6, Object.keys(fCrlf).join(","));
const fWide = A.parseFields(Q.replace("【时期】", "\u3000【时期】\u3000"));
ok("parseFields 容忍标记两侧全角空格", fWide["前提"] === "攻城受挫，部队减员过半。", fWide["时期"]);

/* ---------- 泄漏自检 ---------- */
const leakHits = A.checkLeak({
  period: "1927年，湘赣边界。",
  premise: "此时“工农武装割据”的提法已经成形。",
  result: "局面变了。",
  answer: "\"工农武装割据\"", points: "",
});
ok("题面写了答案 → 命中", leakHits.length > 0, leakHits.join(","));
const clean = { period: "1927年，湘赣边界。", premise: "攻城受挫，部队减员过半。", result: "红军发展到万余人。", answer: "\"工农武装割据\"", points: "转向农村｜三者结合" };
ok("干净的题面 → 不命中", A.checkLeak(clean).length === 0);
ok("答案主干（去引号）也能被识别", A.leakWords({ answer: "《中华人民共和国土地改革法》", points: "" }).some(w => w.includes("土地改革法")));

/* ---------- 去重 ---------- */
const recent = [{ a: "\"工农武装割据\"", p: "1927年", pc: "攻打长沙的计划受挫，部队从五千人减到不足千人，补给断绝。" }];
ok("同一答案 → 判重复", !!A.isRepeat({ answer: "\"工农武装割据\"", premise: "别的前提文字" }, recent));
ok("答案包含关系 → 判重复", !!A.isRepeat({ answer: "工农武装割据道路", premise: "别的前提文字" }, recent));
ok("不同答案 → 不判重复", !A.isRepeat({ answer: "遵义会议", premise: "第五次反围剿失败，中央红军被迫长征。" }, recent));
ok("整段题面相同 → 判重复", !!A.isRepeat({ answer: "别的政策", premise: "攻打长沙的计划受挫，部队从五千人减到不足千人，补给断绝。" }, recent));
ok("空清单 → 不判重复", !A.isRepeat({ answer: "任意", premise: "任意" }, []));

/* ---------- 判卷标记 ---------- */
ok("识别 correct", A.parseVerdict("[[V:correct]]\n【作用】…") === "correct");
ok("识别 reveal（大小写与空格容错）", A.parseVerdict("  [[ v : reveal ]]") === "reveal");
ok("没标记 → 空串", A.parseVerdict("模型没按格式回") === "");
ok("stripMarkText 去掉完整标记", A.stripMarkText("[[V:wrong]]\n【差在哪】…") === "【差在哪】…");
ok("stripMarkText 去掉流式半截标记", A.stripMarkText("正文[[V:corr") === "正文");

/* ---------- 渲染 md ---------- */
ok("md 转义尖括号", A.md("<script>alert(1)</script>").includes("&lt;script&gt;") && !A.md("<script>").includes("<script>"));
ok("md 支持粗体", A.md("**重点**").includes("<b>重点</b>"));
ok("md 字段标记上色", A.md("【作用】\n做事").includes('class="fld"'));
ok("md ※ 免责行特殊处理", A.md("※ 本段是推演").includes('class="dis"'));
ok("md 列表成 ul", A.md("- 一\n- 二").includes("<ul><li>一</li><li>二</li></ul>"));

/* ---------- 时期范围 ---------- */
ok("yearOf 取到年份", A.yearOf("1935年1月，遵义。") === 1935);
ok("yearOf 取不到返回 null", A.yearOf("很久以前") === null);
ok("inEra 边界内", A.inEra(1940, "war") === true);
ok("inEra 边界外", A.inEra(1930, "war") === false);
ok("抗战从 1931 年算起", A.inEra(1931, "war") === true, "1931 应属于抗战与解放");
ok("民国前期从 1912 年算起", A.inEra(1912, "republic") === true && A.inEra(1911, "republic") === false, "1911 应属于晚清");
ok("inEra 不限时期一律通过", A.inEra(1000, "any") === true);
ok("未知时期回落成不限", A.eraById("bogus").id === "any");
ok("六个时期都在", A.ERAS.length === 6, A.ERAS.map(e => e.id).join(","));

/* ---------- 刷新恢复（normalise） ---------- */
const judging = {
  phase: "judging", q: { premise: "前提", result: "结果", answer: "答案" }, qRaw: "原文",
  tries: ["第一手"], rounds: [{ fb: "旧判定", verdict: "wrong" }], draft: "",
};
const n1 = A.normalise(judging);
ok("判卷中刷新 → 回到 question", n1.phase === "question", n1.phase);
ok("判卷中刷新 → 退回那次尝试", n1.tries.length === 0, n1.tries.length);
ok("判卷中刷新 → 答案回到输入框", n1.draft === "第一手", n1.draft);
const n2 = A.normalise({ ...judging, draft: "已经写的新内容" });
ok("已有草稿时不被覆盖", n2.draft === "已经写的新内容", n2.draft);
const nGiveUp = A.normalise({ ...judging, revealPending: true });
ok("公布途中刷新 → 不吞掉上一次作答", nGiveUp.tries.length === 1 && nGiveUp.phase === "question", nGiveUp.tries.length + "/" + nGiveUp.phase);
const mapBase = { phase: "correct", q: { premise: "前提", result: "结果", answer: "答案" }, qRaw: "原文", verdict: "correct", tries: ["答案"] };
const nLoading = A.normalise({ ...mapBase, t: { phase: "loading", fb: "" } });
ok("刷新时理论对照 loading → 可重试的 error", nLoading.t && nLoading.t.phase === "error" && /重试/.test(nLoading.t.fb), nLoading.t && nLoading.t.phase);
const nDone = A.normalise({ ...mapBase, t: { phase: "done", fb: "理论正文" } });
ok("刷新保留理论对照完成态", nDone.t && nDone.t.phase === "done" && nDone.t.fb === "理论正文", nDone.t && nDone.t.phase);
const nErr = A.normalise({ ...mapBase, t: { phase: "error", fb: "网络断了" } });
ok("刷新保留理论对照失败态", nErr.t && nErr.t.phase === "error" && nErr.t.fb === "网络断了", nErr.t && nErr.t.phase);
ok("asking 刷新 → idle", A.normalise({ phase: "asking" }).phase === "idle");
ok("未知 phase → idle", A.normalise({ phase: "乱写" }).phase === "idle");
ok("没有题的 question → idle", A.normalise({ phase: "question", q: null }).phase === "idle");
ok("非法 era → any", A.normalise({ era: "bogus" }).era === "any");
ok("rounds 过滤掉坏数据", A.normalise({ rounds: [{ fb: "好" }, null, { fb: 1 }] }).rounds.length === 1);
ok("normalise(null) 返回空白局", A.normalise(null).phase === "idle" && A.normalise(null).score === 0);

/* ---------- 汇总 ---------- */
let fail = 0;
console.log("\n============ 纯函数单测 ============");
for (const r of results) {
  if (!r.pass) fail++;
  console.log((r.pass ? " PASS  " : "*FAIL*  ") + r.name + (r.detail ? "   [" + r.detail + "]" : ""));
}
console.log(`\n合计 ${results.length} 项，失败 ${fail} 项`);
process.exit(fail ? 1 : 0);
