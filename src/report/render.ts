import { readFileSync } from 'node:fs';
import pc from 'picocolors';
import type { BackfillResult, Coverage } from '../backfill.js';
import { severityRank, type Severity } from '../config.js';
import type { Finding } from '../detectors/types.js';
import { findingUrl } from '../sinks.js';
import { poweredByHelius } from '../style.js';
import type { CheckStatus, Grade, Posture, PostureCheck } from './posture.js';

export interface ReportData {
    generatedAt: Date;
    lookbackDays: number;
    posture: Posture;
    findings: Finding[];
    coverage: BackfillResult[];
    /** Shown in place of the coverage table when no scans ran. */
    coverageNote?: string;
}

const STATUS_ICON: Record<CheckStatus, string> = { pass: '✓', warn: '!', fail: '✕', info: 'i' };
const STATUS_COLOR: Record<CheckStatus, (s: string) => string> = {
    pass: pc.green,
    warn: pc.yellow,
    fail: pc.red,
    info: pc.dim,
};
const TERMINAL_ACTIVITY_ROWS = 25;

export function renderTerminal(report: ReportData): string {
    const { posture } = report;
    const out: string[] = [
        '',
        `${pc.bold('Watchtower')}  ${pc.bold('Security posture')}  ${gradeColor(posture.grade)(pc.bold(`${posture.grade} · ${posture.score}/100`))}  ${pc.dim(posture.basis)}`,
        ...posture.rubric.map((line) => pc.dim(line)),
        '',
    ];

    for (const subject of posture.subjects) {
        out.push(
            `${pc.bold(subject.label)} ${gradeColor(subject.grade)(`${subject.grade} ${subject.score}`)} ${pc.dim(`${subject.kind} ${subject.address}`)}`,
        );
        for (const check of subject.checks) {
            out.push(
                `  ${STATUS_COLOR[check.status](STATUS_ICON[check.status])} ${check.title}${check.penalty ? STATUS_COLOR[check.status](` −${check.penalty}`) : ''}`,
            );
            out.push(`    ${pc.dim(check.detail)}`);
            if (check.fix) out.push(`    ${pc.dim(`Fix: ${check.fix}`)}`);
        }
        out.push('');
    }

    const notable = newestFirst(report.findings).filter((f) => severityRank(f.severity) >= severityRank('medium'));
    out.push(pc.bold(`Activity in the last ${report.lookbackDays} days`));
    if (notable.length === 0) out.push(pc.dim('  No medium-or-higher events.'));
    for (const f of notable.slice(0, TERMINAL_ACTIVITY_ROWS)) {
        out.push(`  ${pc.dim(when(f).padEnd(16))}  ${severityTag(f.severity)}  ${f.title} ${pc.dim(`· ${f.subjectLabel}`)}`);
    }
    if (notable.length > TERMINAL_ACTIVITY_ROWS) {
        out.push(pc.dim(`  …and ${notable.length - TERMINAL_ACTIVITY_ROWS} more in the HTML report`));
    }
    out.push('');

    out.push(pc.bold('Coverage'));
    for (const c of report.coverage) {
        const { label, detail } = c.summary;
        const status = c.coverage === 'complete' ? pc.green(label) : c.coverage === 'failed' ? pc.red(label) : pc.yellow(label);
        out.push(
            `  ${c.plan.label}: ${c.progress.scannedTransactions.toLocaleString('en-US')} scanned, ${c.progress.matchedTransactions} matched, ${status} ${pc.dim(`(${c.progress.creditsCharged} credits)`)}`,
        );
        if (c.coverage !== 'complete') out.push(pc.dim(`    ${detail}`));
    }
    out.push('', poweredByHelius());
    return out.join('\n');
}

function penaltyBadge(check: PostureCheck): string {
    return check.penalty ? ` <span class="penalty ${check.status}">−${check.penalty}</span>` : '';
}

const TONE_COLOR: Record<ReturnType<typeof tone>, (s: string) => string> = { good: pc.green, ok: pc.yellow, bad: pc.red };

function gradeColor(grade: Grade): (s: string) => string {
    return TONE_COLOR[tone(grade)];
}

function severityTag(severity: Severity): string {
    const text = severity.toUpperCase().padEnd(8);
    if (severity === 'critical' || severity === 'high') return pc.red(text);
    if (severity === 'medium') return pc.yellow(text);
    return pc.dim(text);
}

function newestFirst(findings: Finding[]): Finding[] {
    return [...findings].sort((a, b) => b.slot - a.slot);
}

function when(f: Finding): string {
    return f.blockTime ? new Date(f.blockTime * 1000).toISOString().replace('T', ' ').slice(0, 16) : `slot ${f.slot}`;
}

export function renderHtml(report: ReportData): string {
    const { posture } = report;
    const counts = new Map<Severity, number>();
    for (const f of report.findings) counts.set(f.severity, (counts.get(f.severity) ?? 0) + 1);
    const kinds = (kind: string) => posture.subjects.filter((s) => s.kind === kind).length;

    const subjects = posture.subjects
        .map(
            (s) => `
    <section class="card">
      <header class="card-head">
        <div>
          <div class="eyebrow">${esc(s.kind)}</div>
          <h2>${esc(s.label)}</h2>
          <a class="mono muted" href="https://orbmarkets.io/address/${esc(s.address)}" target="_blank" rel="noopener">${esc(s.address)}</a>
        </div>
        <span class="grade-chip tone-${tone(s.grade)}">${s.grade}<small>${s.score}</small></span>
      </header>
      <ul class="checks">${s.checks
          .map(
              (c) => `
        <li class="check ${c.status}">
          <span class="dot">${STATUS_ICON[c.status]}</span>
          <div><strong>${esc(c.title)}</strong>${penaltyBadge(c)}<p>${esc(c.detail)}</p>${c.fix ? `<p class="fix"><span>How to fix:</span> ${esc(c.fix)}</p>` : ''}</div>
        </li>`,
          )
          .join('')}
      </ul>
    </section>`,
        )
        .join('');

    const rows = newestFirst(report.findings)
        .map(
            (f) => `
          <tr>
            <td class="mono nowrap">${esc(when(f))}</td>
            <td><span class="pill sev-${f.severity}">${f.severity}</span></td>
            <td>
              <strong>${esc(f.title)}</strong>
              <div class="muted">${esc(f.description)}</div>
              <details>
                <summary>Details</summary>
                <dl>${Object.entries(f.details)
                    .map(([k, v]) => `<dt>${esc(k)}</dt><dd class="mono">${esc(v)}</dd>`)
                    .join('')}</dl>
              </details>
            </td>
            <td>${esc(f.subjectLabel)}</td>
            <td><a class="mono" href="${findingUrl(f)}" target="_blank" rel="noopener">${f.signature ? `${esc(f.signature.slice(0, 8))}…` : 'View'}</a></td>
          </tr>`,
        )
        .join('');

    const coverage = report.coverage
        .map(
            (c) => `
          <tr>
            <td>${esc(c.plan.label)}${c.coverage === 'complete' ? '' : `<div class="muted small">${esc(c.summary.detail)}</div>`}</td>
            <td class="mono muted">${esc(c.plan.address)}</td>
            <td class="num">${c.progress.scannedTransactions.toLocaleString('en-US')}</td>
            <td class="num">${c.progress.matchedTransactions.toLocaleString('en-US')}</td>
            <td>${coverageStatus(c)}</td>
            <td class="num">${c.progress.creditsCharged}</td>
          </tr>`,
        )
        .join('');

    return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Watchtower Report</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>${STYLES}</style>
</head>
<body>
<nav class="topbar">
  <div class="wrap topbar-inner">
    <span class="brand">Watchtower <span class="muted">Security report</span></span>
    ${POWERED_BY}
  </div>
</nav>
<main class="wrap">
  <section class="hero card">
    <div class="grade-tile tone-${tone(posture.grade)}">${posture.grade}</div>
    <div class="hero-body">
      <div class="eyebrow">Security posture</div>
      <h1>${posture.score}<span class="muted">/100</span></h1>
      <p class="muted">${esc(posture.basis)} History covers the last ${report.lookbackDays} days, from Helius Parsed Events.</p>
      <details class="rubric"><summary>How grading works</summary>${posture.rubric.map((line) => `<p>${esc(line)}</p>`).join('')}</details>
      <p class="muted small mono">Generated ${esc(report.generatedAt.toISOString().slice(0, 16).replace('T', ' '))} UTC</p>
    </div>
    <div class="stats">
      ${stat('Programs', kinds('program'))}
      ${stat('Multisigs', kinds('multisig'))}
      ${stat('Mints', kinds('mint'))}
      ${stat('Critical', counts.get('critical') ?? 0, 'sev-critical')}
      ${stat('High', counts.get('high') ?? 0, 'sev-high')}
      ${stat('Medium', counts.get('medium') ?? 0, 'sev-medium')}
    </div>
  </section>

  <div class="grid">${subjects}
  </div>

  <section class="card">
    <header class="card-head"><div><div class="eyebrow">Activity</div><h2>${report.findings.length} event${report.findings.length === 1 ? '' : 's'}</h2></div></header>
    ${
        report.findings.length === 0
            ? '<p class="muted">No security-relevant events in the scanned window.</p>'
            : `<div class="table-wrap"><table>
        <thead><tr><th>Time (UTC)</th><th>Severity</th><th>Event</th><th>Subject</th><th>Transaction</th></tr></thead>
        <tbody>${rows}
        </tbody>
      </table></div>`
    }
  </section>

  <section class="card">
    <header class="card-head"><div><div class="eyebrow">Coverage</div><h2>Parsed Events scans</h2></div></header>
    <div class="table-wrap"><table>
      <thead><tr><th>Scan</th><th>Address</th><th class="num">Scanned</th><th class="num">Matched</th><th>Status</th><th class="num">Credits</th></tr></thead>
      <tbody>${coverage || `<tr><td colspan="6" class="muted">${esc(report.coverageNote ?? 'No history scans ran for this report.')}</td></tr>`}
      </tbody>
    </table></div>
  </section>

  <footer class="muted small">
    <p>Watchtower is open source. History from <strong>Helius Parsed Events</strong>, live alerts from <strong>Helius Parsed Streams</strong>. Transactions open in <a href="https://orbmarkets.io" target="_blank" rel="noopener">Orb</a>.</p>
    ${POWERED_BY}
  </footer>
</main>
</body>
</html>`;
}

const COVERAGE_PILL: Record<Coverage, string> = { complete: 'ok', 'recent-only': 'sev-info', behind: 'sev-medium', failed: 'sev-high' };

function coverageStatus(c: BackfillResult): string {
    return `<span class="pill ${COVERAGE_PILL[c.coverage]}" title="${esc(c.summary.detail)}">${esc(c.summary.label)}</span>`;
}

function stat(label: string, value: number, className = ''): string {
    return `<div class="stat"><div class="eyebrow">${label}</div><div class="stat-value ${value > 0 ? className : ''}">${value}</div></div>`;
}

function tone(grade: Grade): 'good' | 'ok' | 'bad' {
    if (grade === 'A' || grade === 'B') return 'good';
    if (grade === 'C') return 'ok';
    return 'bad';
}

function esc(text: string): string {
    return text.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
}

/** A data URI rather than inline SVG, so the logo's SVG ids stay isolated. */
const HELIUS_LOGO_URI = `data:image/svg+xml;base64,${readFileSync(new URL('../../assets/brand/Helius-Horizontal-Logo.svg', import.meta.url)).toString('base64')}`;

const POWERED_BY = `<a class="powered" href="https://www.helius.dev" target="_blank" rel="noopener"><span>Powered by</span><img src="${HELIUS_LOGO_URI}" alt="Helius" width="86" height="18"></a>`;

const STYLES = `
:root {
  --brand: #e84326;
  --bg: #ffffff; --card: #ffffff; --card-2: #fafafa;
  --fg: #171717; --muted: #616161;
  --border: #e5e5e5; --hairline: rgba(20, 17, 15, 0.06);
  --success: #039855; --warning: #dc6803; --danger: #d92d20; --info: #1570ef;
  --success-bg: #ecfdf3; --warning-bg: #fffaeb; --danger-bg: #fef3f2; --info-bg: #eff8ff; --brand-bg: #fef3ef;
  --shadow: inset 0 1px 0 0 rgb(255 255 255 / 0.7), 0 1px 2px 0 rgb(16 15 13 / 0.04), 0 2px 6px -1px rgb(16 15 13 / 0.06);
  --radius: 0.5rem;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0a0a0a; --card: #161616; --card-2: #202020;
    --fg: #edeef0; --muted: #b3b3b3;
    --border: rgba(255, 255, 255, 0.1); --hairline: rgba(255, 255, 255, 0.06);
    --success: #32d583; --warning: #fdb022; --danger: #f97066; --info: #53b1fd;
    --success-bg: rgba(50, 213, 131, 0.12); --warning-bg: rgba(253, 176, 34, 0.12); --danger-bg: rgba(249, 112, 102, 0.12);
    --info-bg: rgba(83, 177, 253, 0.12); --brand-bg: rgba(232, 67, 38, 0.14);
    --shadow: inset 0 1px 0 0 rgb(255 255 255 / 0.05), 0 1px 2px 0 rgb(0 0 0 / 0.4);
  }
}
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body { margin: 0; background: var(--bg); color: var(--fg); font: 400 14px/1.5 Inter, system-ui, -apple-system, sans-serif; -webkit-font-smoothing: antialiased; }
a { color: inherit; text-decoration-color: var(--border); text-underline-offset: 3px; }
a:hover { color: var(--brand); text-decoration-color: currentColor; }
h1, h2 { margin: 0; letter-spacing: -0.02em; }
h1 { font-size: 36px; line-height: 1.15; font-weight: 600; }
h2 { font-size: 18px; line-height: 1.35; font-weight: 600; }
p { margin: 0; }
.mono { font-family: 'IBM Plex Mono', ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12.5px; word-break: break-all; }
.muted { color: var(--muted); }
.small { font-size: 12px; }
.nowrap { white-space: nowrap; }
.num { text-align: right; font-variant-numeric: tabular-nums; }
.eyebrow { font-size: 11px; font-weight: 600; letter-spacing: 0.06em; text-transform: uppercase; color: var(--muted); margin-bottom: 4px; }
.wrap { max-width: 1120px; margin: 0 auto; padding: 0 16px; }
.topbar { border-bottom: 1px solid var(--border); background: var(--bg); position: sticky; top: 0; z-index: 10; }
.topbar-inner { display: flex; align-items: center; justify-content: space-between; gap: 12px; height: 56px; }
.brand { display: inline-flex; align-items: baseline; gap: 8px; font-weight: 600; font-size: 15px; letter-spacing: -0.01em; }
.brand .muted { font-weight: 400; font-size: 13px; }
.powered { display: inline-flex; align-items: center; gap: 8px; color: var(--muted); font-size: 12px; text-decoration: none; }
.powered:hover { color: var(--fg); }
.powered img { display: block; height: 18px; width: auto; }
main.wrap { padding-top: 24px; padding-bottom: 48px; display: grid; grid-template-columns: minmax(0, 1fr); gap: 16px; }
.card { background: var(--card); border: 1px solid var(--border); border-radius: var(--radius); box-shadow: var(--shadow); padding: 20px; min-width: 0; }
.card-head { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; margin-bottom: 12px; }
.card-head a.mono { display: inline-block; margin-top: 2px; }
.grid { display: grid; gap: 16px; grid-template-columns: repeat(auto-fit, minmax(min(100%, 440px), 1fr)); }
.hero { display: grid; grid-template-columns: auto 1fr; gap: 20px; align-items: center; }
.hero-body p { margin-top: 6px; max-width: 520px; }
.grade-tile { width: 88px; height: 88px; border-radius: 12px; display: grid; place-items: center; font-size: 44px; font-weight: 700; letter-spacing: -0.02em; border: 1px solid currentColor; }
.stats { grid-column: 1 / -1; display: grid; grid-template-columns: repeat(auto-fit, minmax(110px, 1fr)); border-top: 1px solid var(--hairline); padding-top: 16px; gap: 12px; }
.stat-value { font-size: 22px; font-weight: 600; font-variant-numeric: tabular-nums; letter-spacing: -0.02em; }
.tone-good { color: var(--success); background: var(--success-bg); }
.tone-ok { color: var(--warning); background: var(--warning-bg); }
.tone-bad { color: var(--danger); background: var(--danger-bg); }
.grade-chip { flex: none; display: inline-flex; align-items: baseline; gap: 6px; padding: 4px 10px; border-radius: 999px; font-weight: 700; font-size: 15px; }
.grade-chip small { font-weight: 500; font-size: 12px; opacity: 0.8; }
.checks { list-style: none; margin: 0; padding: 0; }
.check { display: flex; gap: 12px; padding: 12px 0; border-top: 1px solid var(--hairline); }
.check:first-child { border-top: 0; padding-top: 4px; }
.check strong { font-weight: 600; }
.check p { color: var(--muted); margin-top: 2px; overflow-wrap: anywhere; }
.dot { flex: none; width: 20px; height: 20px; margin-top: 1px; border-radius: 50%; display: grid; place-items: center; font-size: 11px; font-weight: 700; }
.check.pass .dot { color: var(--success); background: var(--success-bg); }
.check.warn .dot { color: var(--warning); background: var(--warning-bg); }
.check.fail .dot { color: var(--danger); background: var(--danger-bg); }
.check.info .dot { color: var(--muted); background: var(--card-2); }
.penalty { display: inline-block; margin-left: 6px; padding: 0 6px; border-radius: 4px; font-size: 12px; font-weight: 600; font-variant-numeric: tabular-nums; }
.penalty.warn { color: var(--warning); background: var(--warning-bg); }
.penalty.fail { color: var(--danger); background: var(--danger-bg); }
.check p.fix { color: var(--fg); }
.check p.fix span { color: var(--muted); font-weight: 500; }
.rubric p { margin-top: 4px; font-size: 13px; }
.table-wrap { overflow-x: auto; margin: 0 -20px; padding: 0 20px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th { text-align: left; font-size: 11px; font-weight: 600; letter-spacing: 0.06em; text-transform: uppercase; color: var(--muted); padding: 8px; border-bottom: 1px solid var(--border); white-space: nowrap; }
td { padding: 12px 8px; border-bottom: 1px solid var(--hairline); vertical-align: top; }
tbody tr:last-child td { border-bottom: 0; }
td strong { font-weight: 600; }
.pill { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 11px; font-weight: 600; letter-spacing: 0.04em; text-transform: uppercase; white-space: nowrap; }
.sev-critical { color: var(--brand); background: var(--brand-bg); }
.sev-high { color: var(--danger); background: var(--danger-bg); }
.sev-medium { color: var(--warning); background: var(--warning-bg); }
.sev-low { color: var(--info); background: var(--info-bg); }
.sev-info { color: var(--muted); background: var(--card-2); }
.pill.ok { color: var(--success); background: var(--success-bg); }
.stat-value.sev-critical, .stat-value.sev-high, .stat-value.sev-medium { background: none; }
details { margin-top: 6px; }
summary { cursor: pointer; color: var(--muted); font-size: 12px; }
summary:hover { color: var(--fg); }
dl { display: grid; grid-template-columns: max-content 1fr; gap: 4px 12px; margin: 8px 0 0; }
dt { color: var(--muted); font-size: 12px; }
dd { margin: 0; }
footer { display: grid; justify-items: center; gap: 10px; text-align: center; padding-top: 16px; }
footer strong { color: var(--fg); font-weight: 500; }
@media (max-width: 640px) {
  .brand .muted { display: none; }
  .hero { grid-template-columns: 1fr; }
  h1 { font-size: 28px; }
  dl { grid-template-columns: 1fr; }
}
`;
