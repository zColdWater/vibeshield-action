#!/usr/bin/env node
/**
 * VibeShield Security Gate — Zero-dependency GitHub Action (Node 20+/22)
 * Calls https://shipbastion.com/api/free-scan and posts a clean, idempotent PR security table.
 */
import fs from "node:fs";

export const COMMENT_MARKER = "<!-- vibeshield-security-gate -->";

export function normalizeTargetUrl(raw) {
  const s = String(raw || "").trim();
  if (!s) throw new Error("Input 'url' is required (e.g. https://yourapp.vercel.app)");
  const withProto = /^https?:\/\//i.test(s) ? s : `https://${s}`;
  const u = new URL(withProto);
  if (!["http:", "https:"].includes(u.protocol)) throw new Error(`Unsupported URL protocol: ${u.protocol}`);
  return u.toString();
}

export function buildMarkdownReport(data, { apiBase = "https://shipbastion.com", failBelow = 0 } = {}) {
  const cleanBase = String(apiBase || "https://shipbastion.com").replace(/\/+$/, "");
  const a = data.assessment || {};
  const score = Number(a.score ?? 0);
  const grade = String(a.grade || (score >= 90 ? "A+" : score >= 80 ? "A" : score >= 70 ? "B" : score >= 55 ? "C" : "F"));
  const host = String(data.hostname || new URL(data.targetUrl || "https://example.com").hostname).replace(/^www\./i, "");
  const crit = Number(a.criticalCount || 0);
  const high = Number(a.highCount || 0);
  const med = Number(a.mediumCount || 0);
  const low = Number(a.lowCount || 0);

  const b = data.bundles || {};
  const secCount = Number(b.secretsFoundCount || (data.secretsFound || []).length || 0);
  const hdrs = data.headers || {};
  const supa = data.supabase || {};
  const fb = data.firebase || {};
  const tls = data.tls || {};
  const probes = data.probes || {};
  const findings = Array.isArray(data.findings) ? data.findings : [];

  const gatePassed = !(failBelow > 0 && score < failBelow);
  const statusIcon = crit > 0 || !gatePassed ? "🔴" : high > 0 ? "🟠" : score >= 80 ? "🟢" : "🟡";
  const reportUrl = `${cleanBase}/?url=${encodeURIComponent(host)}`;
  const trustUrl = `${cleanBase}/trust/${encodeURIComponent(host)}`;
  const badgeUrl = `${cleanBase}/badge/trust/${encodeURIComponent(host)}.svg`;

  const dbStatus = supa.serviceRoleLeaked || (supa.exposedTables || []).length > 0 || (fb.exposedEndpoints || []).length > 0
    ? "Exposed"
    : (supa.detected || fb.detected ? "Protected" : "None detected");
  const tlsStatus = data.tlsHttps ? `${tls.protocol || "HTTPS"}${tls.daysRemaining != null ? ` (${tls.daysRemaining}d)` : ""}` : "HTTP only";
  const probeStatus = Number(probes.exposedCount || 0) > 0
    ? `${probes.exposedCount} exposed / ${probes.totalChecked || 28}`
    : `${probes.totalChecked || 28}/${probes.totalChecked || 28} blocked`;

  const lines = [
    COMMENT_MARKER,
    `### ${statusIcon} VibeShield Security Gate — \`${host}\``,
    "",
    `| Security Score | Grade | Critical | High | Medium | Low | Gate |`,
    `|:---:|:---:|:---:|:---:|:---:|:---:|:---:|`,
    `| **${score} / 100** | **${grade}** | **${crit}** | **${high}** | ${med} | ${low} | ${gatePassed ? "PASS" : `FAIL (< ${failBelow})`} |`,
    "",
    `| Audit Dimension | Result |`,
    `|:---|:---|`,
    `| Client JS Secrets | ${secCount > 0 ? `**${secCount} potential exposure(s)**` : "0 leaks across scanned bundles"} |`,
    `| Supabase / Firebase RLS | ${dbStatus} |`,
    `| Security Headers | ${hdrs.passed ?? 0} / ${hdrs.total ?? 10} passed |`,
    `| TLS 443 & Sensitive Probes | ${tlsStatus} · ${probeStatus} |`,
  ];

  if (findings.length > 0) {
    lines.push("", "**Top Findings (titles only — zero sensitive values exposed in PR logs):**");
    for (const f of findings.slice(0, 5)) {
      const sev = String(f.severity || "info").toUpperCase();
      lines.push(`- **[${sev}]** ${String(f.title || f.id || "Security finding").replace(/\r?\n/g, " ")}`);
    }
    if (findings.length > 5) {
      lines.push(`- _+${findings.length - 5} more finding(s) in full live report_`);
    }
  }

  lines.push(
    "",
    `[![Verified by ShipBastion](${badgeUrl})](${trustUrl})`,
    "",
    `> **Full Cursor Fix & 24/7 Monitor ->** ${reportUrl}  `,
    `> **Public Trust Page ->** ${trustUrl}`,
  );
  return { markdown: lines.join("\n"), score, grade, crit, high, host, reportUrl, trustUrl, gatePassed };
}

function appendFileSafe(filePath, content) {
  if (!filePath) return;
  fs.appendFileSync(filePath, content, "utf8");
}

function getPrNumber() {
  const evPath = process.env.GITHUB_EVENT_PATH;
  if (!evPath || !fs.existsSync(evPath)) return null;
  try {
    const ev = JSON.parse(fs.readFileSync(evPath, "utf8"));
    return ev?.pull_request?.number || ev?.issue?.number || null;
  } catch {
    return null;
  }
}

async function upsertPrComment({ repo, prNumber, token, body }) {
  const api = process.env.GITHUB_API_URL || "https://api.github.com";
  const headers = {
    Authorization: `Bearer ${token}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "vibeshield-action/1.0",
    "Content-Type": "application/json",
  };
  const listRes = await fetch(`${api}/repos/${repo}/issues/${prNumber}/comments?per_page=100`, { headers });
  let existingId = null;
  if (listRes.ok) {
    const comments = await listRes.json();
    const match = Array.isArray(comments) ? comments.find((c) => typeof c.body === "string" && c.body.includes(COMMENT_MARKER)) : null;
    if (match?.id) existingId = match.id;
  }
  const endpoint = existingId
    ? `${api}/repos/${repo}/issues/comments/${existingId}`
    : `${api}/repos/${repo}/issues/${prNumber}/comments`;
  const method = existingId ? "PATCH" : "POST";
  const res = await fetch(endpoint, { method, headers, body: JSON.stringify({ body }) });
  if (!res.ok) {
    const txt = await res.text().catch(() => "");
    console.warn(`VibeShield warning: unable to ${method} PR comment (HTTP ${res.status}): ${txt.slice(0, 180)}`);
  } else {
    console.log(`VibeShield: ${existingId ? "updated" : "posted"} security gate comment on PR #${prNumber}`);
  }
}

export async function runScan(targetUrl, apiBase = "https://shipbastion.com") {
  const cleanBase = String(apiBase || "https://shipbastion.com").replace(/\/+$/, "");
  const endpoints = [`${cleanBase}/api/free-scan?url=${encodeURIComponent(targetUrl)}`, `${cleanBase}/api/scan?url=${encodeURIComponent(targetUrl)}`];
  let lastErr = "VibeShield scan failed";
  for (const ep of endpoints) {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), 35_000);
    try {
      const res = await fetch(ep, {
        headers: { Accept: "application/json", "User-Agent": "vibeshield-action/1.0" },
        signal: ctl.signal,
      });
      if (res.status === 404) {
        lastErr = `HTTP 404 on ${ep}`;
        continue;
      }
      const data = await res.json().catch(() => ({}));
      if (!res.ok || data.ok === false) {
        throw new Error(data.error || `VibeShield API returned HTTP ${res.status}`);
      }
      return data;
    } finally {
      clearTimeout(timer);
    }
  }
  throw new Error(lastErr);
}

async function main() {
  const targetUrl = normalizeTargetUrl(process.env.INPUT_URL);
  const apiBase = String(process.env.INPUT_API_BASE || "https://shipbastion.com").replace(/\/+$/, "");
  const failBelow = Math.max(0, Math.min(100, Number(process.env.INPUT_FAIL_BELOW || 0) || 0));
  const commentPr = String(process.env.INPUT_COMMENT_PR || "true").toLowerCase() !== "false";

  console.log(`VibeShield: auditing ${targetUrl} via ${apiBase}/api/free-scan ...`);
  const data = await runScan(targetUrl, apiBase);
  const report = buildMarkdownReport(data, { apiBase, failBelow });

  console.log(`VibeShield Result: ${report.host} -> ${report.score}/100 (Grade ${report.grade}) | Critical=${report.crit} High=${report.high}`);

  appendFileSafe(
    process.env.GITHUB_OUTPUT,
    [
      `score=${report.score}`,
      `grade=${report.grade}`,
      `critical-count=${report.crit}`,
      `high-count=${report.high}`,
      `report-url=${report.reportUrl}`,
      `trust-url=${report.trustUrl}`,
      "",
    ].join("\n")
  );
  appendFileSafe(process.env.GITHUB_STEP_SUMMARY, `${report.markdown}\n`);

  const repo = process.env.GITHUB_REPOSITORY;
  const token = process.env.GITHUB_TOKEN;
  const prNumber = getPrNumber();
  if (commentPr && repo && token && prNumber) {
    await upsertPrComment({ repo, prNumber, token, body: report.markdown });
  }

  if (!report.gatePassed) {
    console.error(`VibeShield Security Gate FAILED: score ${report.score}/100 is below fail-below threshold (${failBelow}).`);
    process.exit(1);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err) => {
    console.error(`VibeShield Action error: ${err?.message || err}`);
    process.exit(1);
  });
}
