const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'];
const SEVERITY_LABEL = { info: 'Info', low: 'Low', medium: 'Medium', high: 'High', critical: 'Critical' };
const STATUS_ICON = { pass: '✓', warn: '!', fail: '✕', info: 'i' };
const PHASE_TEXT = {
    starting: 'Starting',
    'catching-up': 'Catching up',
    live: 'Live',
    reconnecting: 'Reconnecting',
    stopped: 'Stopped',
    error: 'Error',
};
const DEFAULT_CONFIG = {
    programs: [],
    multisigs: [],
    mints: [],
    treasuries: [],
    watchedKeys: [],
    alerts: { minSeverity: 'low', sinks: [{ type: 'console' }] },
    backfill: { lookbackDays: 30, maxScannedTransactions: 20000 },
    idlPollMinutes: 10,
};
const EXAMPLE_PROGRAMS = [
    { label: 'Kamino Lend', value: 'KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAYavgmjD' },
    { label: 'Jupiter v6', value: 'JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4' },
    { label: 'Pump AMM', value: 'pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA' },
    { label: 'Drift v2', value: 'dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH' },
];
const EXAMPLE_MINTS = [
    { label: 'JitoSOL', value: 'J1toso1uCk3RLmjorhTtrVwY9HJ7X8V9yYac6Y7kGCPn' },
    { label: 'USDC', value: 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v' },
    { label: 'JUP', value: 'JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN' },
];
const CHANNELS = [
    { id: 'discord', title: 'Discord', description: 'Webhook into a channel', fields: [['url', 'Webhook URL']] },
    { id: 'slack', title: 'Slack', description: 'Incoming webhook', fields: [['url', 'Webhook URL']] },
    {
        id: 'telegram',
        title: 'Telegram',
        description: 'Bot message to a chat',
        fields: [
            ['botToken', 'Bot token'],
            ['chatId', 'Chat ID'],
        ],
    },
    { id: 'webhook', title: 'Webhook', description: 'JSON POST to your endpoint', fields: [['url', 'Endpoint URL']] },
];
const ENV_STEPS = 'cp .env.example .env\n# then set HELIUS_API_KEY=your-key (from dashboard.helius.dev)';
const SERVER_DOWN =
    'Can’t reach the Watchtower server. Is `watchtower serve` still running? Start it again and this page reconnects on its own.';
const BASE58 = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;

let state = null;
let monitorId = new URLSearchParams(location.search).get('monitor');
/** Requests that are not about one monitor. */
const SHARED_ENDPOINTS = new Set(['/api/discover', '/api/monitors']);
let view = 'overview';
let draft = null;
/** The draft as last loaded or saved, to tell whether Setup has unsaved changes. */
let savedDraft = null;
const filters = { minSeverity: 'low', subject: 'all', search: '' };
const fresh = new Set();
const openDetails = new Set();

/** Text children become text nodes, so on-chain strings are never parsed as HTML. */
function h(tag, props = {}, ...children) {
    const el = document.createElement(tag);
    for (const [key, value] of Object.entries(props)) {
        if (value === undefined || value === null || value === false) continue;
        if (key.startsWith('on')) el.addEventListener(key.slice(2).toLowerCase(), value);
        else if (key === 'class') el.className = value;
        else if (key === 'value') el.value = value;
        else if (key === 'checked') el.checked = value;
        else el.setAttribute(key, value === true ? '' : value);
    }
    for (const child of children.flat(Infinity)) {
        if (child === null || child === undefined || child === false) continue;
        el.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return el;
}

/** A <details> whose open state survives re-renders. */
function disclosure(key, props, summary, ...body) {
    return h(
        'details',
        { ...props, open: openDetails.has(key), ontoggle: (e) => (e.target.open ? openDetails.add(key) : openDetails.delete(key)) },
        h('summary', {}, summary),
        ...body,
    );
}

async function api(path, body) {
    const payload = body === undefined || SHARED_ENDPOINTS.has(path) || !monitorId ? body : { monitor: monitorId, ...body };
    let response;
    try {
        response = await fetch(
            path,
            payload === undefined ? {} : { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload) },
        );
    } catch {
        showOffline(true);
        throw new Error(SERVER_DOWN);
    }
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error ?? `HTTP ${response.status}`);
    return data;
}

function toast(message, isError = false) {
    const el = document.getElementById('toast');
    el.textContent = message;
    el.className = `toast${isError ? ' error' : ''}`;
    el.hidden = false;
    clearTimeout(toast.timer);
    toast.timer = setTimeout(() => (el.hidden = true), 4000);
}

const severityRank = (severity) => SEVERITIES.indexOf(severity);
const short = (address) => (address && address.length > 12 ? `${address.slice(0, 4)}…${address.slice(-4)}` : address);
const tone = (grade) => (grade === 'A' || grade === 'B' ? 'good' : grade === 'C' ? 'ok' : 'bad');
const findingUrl = (f) => (f.signature ? `https://orbmarkets.io/tx/${f.signature}` : `https://orbmarkets.io/address/${f.subject}`);
const when = (f) =>
    f.blockTime
        ? new Date(f.blockTime * 1000).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' })
        : `slot ${f.slot.toLocaleString()}`;
const clone = (value) => JSON.parse(JSON.stringify(value));

function choiceCards(choices, onSelect) {
    return h(
        'div',
        { class: 'choice-cards' },
        choices.map((c) =>
            h(
                'button',
                { type: 'button', class: 'choice-card', 'aria-pressed': 'false', onclick: () => onSelect(c.id) },
                h('strong', {}, c.title),
                c.description ? h('span', {}, c.description) : null,
            ),
        ),
    );
}

function chip(label, active, onClick, title) {
    return h('button', { type: 'button', class: 'chip', 'aria-pressed': String(Boolean(active)), title, onclick: onClick }, label);
}

function tag(label, onRemove) {
    return h('span', { class: 'tag' }, label, h('button', { type: 'button', 'aria-label': `Remove ${label}`, onclick: onRemove }, '×'));
}

function field(label, control) {
    return h('label', { class: 'field' }, label, control);
}

function sectionTitle(title, hint) {
    return h('div', { class: 'section-title' }, title, hint ? h('span', { class: 'hint' }, hint) : null);
}

async function loadState() {
    state = await api(monitorId ? `/api/state?monitor=${encodeURIComponent(monitorId)}` : '/api/state');
    monitorId = state.monitor;
}

async function switchMonitor(id) {
    monitorId = id;
    draft = null;
    history.replaceState(null, '', `?monitor=${encodeURIComponent(id)}${location.hash}`);
    await loadState();
    render();
}

async function boot() {
    try {
        await loadState();
    } catch {
        monitorId = null;
        await loadState();
    }
    document.getElementById('setup-tab').hidden = state.readOnly;
    view = location.hash.slice(1) || (!state.configured && !state.readOnly ? 'setup' : 'overview');
    window.addEventListener('hashchange', () => {
        view = location.hash.slice(1) || 'overview';
        render();
    });
    connectEvents();
    render();
    // Fonts swap in after first paint; waiting briefly for them keeps text from re-wrapping in view.
    await Promise.race([document.fonts.ready, new Promise((resolve) => setTimeout(resolve, 1000))]);
    document.body.classList.add('ready');
    for (const type of ['input', 'change']) document.getElementById('view').addEventListener(type, updateSaveBar);
    // The grading popover overlays the page, so it closes on a click elsewhere or Escape.
    document.addEventListener('click', (e) => {
        for (const open of document.querySelectorAll('details.rubric[open]')) if (!open.contains(e.target)) open.open = false;
    });
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') for (const open of document.querySelectorAll('details.rubric[open]')) open.open = false;
    });
}

function go(next) {
    if (location.hash === `#${next}`) render();
    else location.hash = next;
}

function showOffline(offline) {
    document.getElementById('offline').hidden = !offline;
    if (!offline) return;
    document.getElementById('status').dataset.phase = 'error';
    document.getElementById('status-text').textContent = 'Disconnected';
}

/** EventSource reconnects on its own; after a drop the server may have restarted, so state is reloaded on reopen. */
function connectEvents() {
    const events = new EventSource('/api/events');
    events.addEventListener('error', () => {
        if (events.readyState !== EventSource.OPEN) showOffline(true);
    });
    events.addEventListener('open', async () => {
        if (document.getElementById('offline').hidden) return;
        await loadState();
        showOffline(false);
        render();
    });
    /** Events name their monitor; those for other monitors only update the tab bar. */
    const on = (name, handler) =>
        events.addEventListener(name, (e) => {
            const { monitor, data } = JSON.parse(e.data);
            if (monitor === monitorId) return handler(data);
            if (name === 'status' && state.monitors) {
                state.monitors = state.monitors.map((m) => (m.id === monitor && m.phase !== 'paused' ? { ...m, phase: data.phase } : m));
                renderMonitorTabs();
            }
        });
    events.addEventListener('monitors', (e) => {
        state.monitors = JSON.parse(e.data).data;
        renderMonitorTabs();
        renderPauseControl();
    });
    on('finding', (finding) => {
        if (state.findings.some((f) => f.id === finding.id)) return;
        state.findings = [finding, ...state.findings].slice(0, 300);
        state.severityCounts = { ...state.severityCounts, [finding.severity]: (state.severityCounts?.[finding.severity] ?? 0) + 1 };
        fresh.add(finding.id);
        if (view !== 'setup') render();
    });
    on('status', (status) => {
        state.status = status;
        state.monitors = state.monitors?.map((m) => (m.id === monitorId && m.phase !== 'paused' ? { ...m, phase: status.phase } : m));
        renderMonitorTabs();
        renderStatus();
        if (view === 'overview') render();
    });
    on('log', (entry) => {
        state.logs = [...state.logs.slice(-299), entry];
        if (view === 'activity') renderLog();
    });
    on('report', () => {
        state.reportRunning = true;
        if (view === 'overview') render();
    });
    on('state', (snapshot) => {
        state = snapshot;
        if (view !== 'setup') return render();
        renderMonitorTabs();
        renderPauseControl();
        renderStatus();
    });
}

function render() {
    for (const tab of document.querySelectorAll('.page-tab')) {
        if (tab.dataset.view === view) tab.setAttribute('aria-current', 'page');
        else tab.removeAttribute('aria-current');
    }
    const report = document.getElementById('report-link');
    report.setAttribute('aria-disabled', String(!state.posture));
    report.href = `/report.html?monitor=${encodeURIComponent(monitorId)}`;
    renderMonitorTabs();
    renderPauseControl();
    renderStatus();
    const main = document.getElementById('view');
    main.replaceChildren(...(view === 'activity' ? activityView() : view === 'setup' ? setupView() : overviewView()).filter(Boolean));
    fresh.clear();
}

/** A saved monitor whose runtime is still being created. */
const isStarting = () => !state.configured && state.status?.phase === 'starting';

function renderStatus() {
    if (!document.getElementById('offline').hidden) return;
    const pill = document.getElementById('status');
    if (state.paused) {
        pill.dataset.phase = 'paused';
        document.getElementById('status-text').textContent = 'Stopped';
        return;
    }
    if (!state.configured && !isStarting()) {
        pill.dataset.phase = state.configError ? 'error' : 'stopped';
        document.getElementById('status-text').textContent = 'Not configured';
        return;
    }
    const phase = state.status?.phase ?? 'starting';
    pill.dataset.phase = phase;
    document.getElementById('status-text').textContent = PHASE_TEXT[phase];
}

const MONITOR_TOOLTIP = {
    stop: [
        'Stop Monitoring',
        'Closes the Parsed Streams connection and stops all alerts. The dashboard stays available. When you start again, Watchtower catches up on everything that happened in between, so nothing is missed.',
    ],
    start: [
        'Monitoring is stopped',
        'Nothing is streamed and no alerts are sent. Starting reconnects and catches up with Parsed Events on everything that happened while stopped.',
    ],
};

function monitorName() {
    return state.monitors?.find((m) => m.id === monitorId)?.name ?? 'Watchtower';
}

let creatingMonitor = false;

function setCreatingMonitor(value) {
    creatingMonitor = value;
    renderMonitorTabs();
}

function renderMonitorTabs() {
    document.getElementById('monitor-name').textContent = monitorName();
    const tabs = (state.monitors ?? []).map((m) =>
        h(
            'button',
            {
                type: 'button',
                class: 'monitor-tab',
                'aria-current': m.id === monitorId ? 'true' : 'false',
                title: `${m.name}: ${m.phase === 'paused' ? 'stopped' : m.phase === 'unconfigured' ? 'not configured' : (PHASE_TEXT[m.phase] ?? m.phase).toLowerCase()}`,
                onclick: () => m.id !== monitorId && switchMonitor(m.id),
            },
            h('span', { class: 'dot', 'data-phase': m.phase }),
            h('span', {}, m.name),
        ),
    );
    const name = h('input', { placeholder: 'Monitor name', 'aria-label': 'New monitor name', maxlength: '60' });
    const create = async () => {
        try {
            const created = await api('/api/monitors', { name: name.value });
            creatingMonitor = false;
            await switchMonitor(created.monitor);
            go('setup');
        } catch (error) {
            toast(error.message, true);
        }
    };
    name.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') create();
        if (e.key === 'Escape') setCreatingMonitor(false);
    });
    const adder = state.readOnly
        ? null
        : creatingMonitor
          ? h(
                'span',
                { class: 'monitor-new' },
                name,
                h('button', { type: 'button', class: 'btn btn-primary btn-sm', onclick: create }, 'Create'),
                h('button', { type: 'button', class: 'btn btn-ghost btn-sm', onclick: () => setCreatingMonitor(false) }, 'Cancel'),
            )
          : h('button', { type: 'button', class: 'btn btn-ghost btn-sm', onclick: () => setCreatingMonitor(true) }, '+ New Monitor');
    document.getElementById('monitor-tabs').replaceChildren(...tabs, ...(adder ? [adder] : []));
    if (creatingMonitor) name.focus();
}

async function deleteMonitor() {
    const label = monitorName();
    if (!confirm(`Delete “${label}”? Its configuration and finding history are removed. This cannot be undone.`)) return;
    try {
        const { monitors } = await api('/api/monitors/delete', {});
        toast(`Deleted ${label}`);
        await switchMonitor(monitors[0].id);
    } catch (error) {
        toast(error.message, true);
    }
}

function renderPauseControl() {
    const remove = document.getElementById('delete-button');
    const running = (state.configured || isStarting()) && !state.paused;
    // Deleting the only monitor recreates it empty, so an unsaved one has nothing to delete.
    remove.hidden = state.readOnly || (!state.config && (state.monitors?.length ?? 0) <= 1);
    remove.disabled = running;
    remove.title = running ? 'Stop monitoring to delete this monitor' : 'Removes this monitor’s configuration and finding history';
    remove.onclick = deleteMonitor;
    const button = document.getElementById('pause-button');
    document.getElementById('monitor-control').hidden = state.readOnly || (!state.configured && !isStarting());
    button.disabled = isStarting();
    button.textContent = state.paused ? 'Start Monitoring' : 'Stop Monitoring';
    button.className = `btn ${state.paused ? 'btn-primary' : 'btn-destructive'}`;
    button.onclick = togglePause;
    const [title, body] = MONITOR_TOOLTIP[state.paused ? 'start' : 'stop'];
    document.getElementById('monitor-tooltip').replaceChildren(h('strong', {}, title), body);
}

async function togglePause() {
    const button = document.getElementById('pause-button');
    const resuming = state.paused;
    button.disabled = true;
    button.textContent = resuming ? 'Starting…' : 'Stopping…';
    try {
        state = await api(resuming ? '/api/resume' : '/api/pause', {});
        toast(
            resuming
                ? 'Monitoring started. Catching up on anything missed.'
                : 'Monitoring stopped. No alerts will be sent until you start it again.',
        );
    } catch (error) {
        toast(error.message, true);
    } finally {
        button.disabled = false;
        render();
    }
}

function overviewView() {
    if (!state.configured && !isStarting()) return [notConfigured()];
    const { posture, status, watching } = state;
    const count = (severity) => state.severityCounts?.[severity] ?? 0;
    const grading = !posture && !state.paused && !state.reportError;
    return [
        h(
            'section',
            { class: 'card hero' },
            posture
                ? h('div', { class: `grade-tile tone-${tone(posture.grade)}` }, posture.grade)
                : h('div', { class: `grade-tile tone-none ${grading ? 'skeleton' : ''}` }, grading ? '' : '—'),
            h(
                'div',
                { class: 'row', style: 'justify-content: space-between; align-items: flex-start' },
                h(
                    'div',
                    { class: 'posture-summary' },
                    h('div', { class: 'label' }, 'Security posture'),
                    h(
                        'div',
                        { class: 'score' },
                        posture ? [posture.score, h('span', { class: 'muted' }, '/100')] : grading ? skeletonText('80/100') : '—',
                    ),
                    h(
                        'p',
                        { class: 'muted posture-basis', style: 'margin-top: 4px' },
                        state.reportRunning
                            ? 'Grading upgrade authorities, multisigs, mints and nonce accounts…'
                            : posture
                              ? `${posture.basis} Graded ${new Date(state.reportGeneratedAt).toLocaleString()}.`
                              : state.reportError
                                ? `Grading failed: ${state.reportError}`
                                : isStarting()
                                  ? 'Starting the monitor…'
                                  : 'Waiting for the first grade.',
                    ),
                    posture
                        ? disclosure(
                              'rubric',
                              { class: 'rubric' },
                              'How grading works',
                              h(
                                  'div',
                                  { class: 'rubric-panel' },
                                  posture.rubric.map((line) => h('p', {}, line)),
                              ),
                          )
                        : h(
                              'div',
                              { class: 'rubric rubric-placeholder', 'aria-hidden': 'true', style: grading ? null : 'visibility: hidden' },
                              skeletonText('▸ How grading works'),
                          ),
                ),
                state.readOnly
                    ? null
                    : h(
                          'button',
                          { class: 'btn btn-outline', disabled: state.reportRunning || isStarting(), onclick: refreshReport },
                          state.reportRunning ? 'Grading…' : 'Refresh',
                      ),
            ),
            h(
                'div',
                { class: 'stats' },
                stat('Programs', watching ? Object.keys(watching.programs).length : skeletonText('00')),
                stat('Multisigs', watching?.multisigs ?? skeletonText('00')),
                stat('Mints', watching?.mints ?? skeletonText('00')),
                stat('Treasuries', watching?.treasuries ?? skeletonText('00')),
                stat('Vaults found', watching?.vaults ?? skeletonText('00')),
                stat('Keys protected', watching?.keys ?? skeletonText('00')),
                stat('Critical', count('critical'), 'text-critical'),
                stat('High', count('high'), 'text-high'),
                stat('Medium', count('medium'), 'text-medium'),
            ),
        ),
        posture
            ? h('div', { class: 'grid' }, posture.subjects.map(subjectCard))
            : grading
              ? h('div', { class: 'grid', 'aria-hidden': 'true' }, Array.from({ length: expectedSubjects() }, skeletonSubjectCard))
              : null,
        h('div', { class: 'grid' }, recentActivityCard(), streamCard(status)),
        coverageCard(status),
    ];
}

/** Text-sized placeholder: the hidden text gives it the size of what will replace it. */
function skeletonText(text) {
    return h('span', { class: 'skeleton-text' }, text);
}

/** Posture grades each program, configured multisig and mint. */
function expectedSubjects() {
    const programs = state.watching ? Object.keys(state.watching.programs).length : (state.config?.programs?.length ?? 1);
    return Math.max(1, programs + (state.watching?.mints ?? 0) + (state.config?.multisigs?.length ?? 0));
}

function skeletonSubjectCard() {
    return h(
        'section',
        { class: 'card' },
        h(
            'header',
            { class: 'card-head' },
            h(
                'div',
                {},
                h('div', { class: 'label' }, skeletonText('Program')),
                h('h2', {}, skeletonText('Program name')),
                h('div', { class: 'mono' }, skeletonText('KLend2g3cP87fffoy8q1mQqGKjrxjC8boSyAY')),
            ),
            h('span', { class: 'grade-chip tone-none skeleton' }, 'B', h('small', {}, '80')),
        ),
        h(
            'ul',
            { class: 'checks' },
            [0, 1, 2, 3, 4].map(() =>
                h(
                    'li',
                    { class: 'check' },
                    h('span', { class: 'dot-icon skeleton' }),
                    h(
                        'div',
                        {},
                        h('strong', {}, skeletonText('Upgrades need 5 of 10 signatures')),
                        h('p', {}, skeletonText('Squads v4 multisig, vault 0')),
                    ),
                ),
            ),
        ),
    );
}

function stat(label, value, className = '') {
    return h(
        'div',
        {},
        h('div', { class: 'label' }, label),
        h('div', { class: `stat-value ${Number(value) > 0 ? className : ''}` }, value),
    );
}

function subjectCard(subject) {
    return h(
        'section',
        { class: 'card' },
        h(
            'header',
            { class: 'card-head' },
            h(
                'div',
                {},
                h('div', { class: 'label', style: 'text-transform: capitalize' }, subject.kind),
                h('h2', {}, subject.label),
                h(
                    'a',
                    { class: 'mono muted', href: `https://orbmarkets.io/address/${subject.address}`, target: '_blank', rel: 'noopener' },
                    subject.address,
                ),
            ),
            h('span', { class: `grade-chip tone-${tone(subject.grade)}` }, subject.grade, h('small', {}, subject.score)),
        ),
        h(
            'ul',
            { class: 'checks' },
            subject.checks.map((check) =>
                h(
                    'li',
                    { class: `check ${check.status}` },
                    h('span', { class: 'dot-icon' }, STATUS_ICON[check.status]),
                    h(
                        'div',
                        {},
                        h('strong', {}, check.title),
                        check.penalty
                            ? h('span', { class: `penalty ${check.status}`, title: `Costs ${check.penalty} points` }, `−${check.penalty}`)
                            : null,
                        h('p', {}, check.detail),
                        check.fix ? h('p', { class: 'fix' }, h('span', {}, 'How to fix: '), check.fix) : null,
                    ),
                ),
            ),
        ),
    );
}

function recentActivityCard() {
    const recent = state.findings.filter((f) => severityRank(f.severity) >= severityRank('low')).slice(0, 6);
    return h(
        'section',
        { class: 'card compact' },
        h(
            'header',
            { class: 'card-head' },
            h('div', {}, h('div', { class: 'label' }, 'Activity'), h('h2', {}, 'Latest findings')),
            h('button', { class: 'btn btn-outline btn-sm', onclick: () => go('activity') }, 'View all'),
        ),
        recent.length === 0
            ? h('p', { class: 'empty' }, 'Nothing yet. New findings appear here live.')
            : h('ul', { class: 'feed' }, recent.map(feedItem)),
    );
}

function streamCard(status) {
    const subs = status?.subscriptions ?? [];
    return h(
        'section',
        { class: 'card' },
        h(
            'header',
            { class: 'card-head' },
            h('div', {}, h('div', { class: 'label' }, 'Parsed Streams'), h('h2', {}, PHASE_TEXT[status?.phase ?? 'starting'])),
            h(
                'div',
                { class: 'muted small num' },
                status?.serverSlot ? h('div', {}, `slot ${status.serverSlot.toLocaleString()}`) : null,
                status?.connectedSince ? h('div', {}, `connected ${new Date(status.connectedSince).toLocaleTimeString()}`) : null,
            ),
        ),
        status?.error ? h('p', { class: 'error-text' }, status.error) : null,
        h(
            'div',
            { class: 'table-wrap' },
            h(
                'table',
                { class: 'responsive-table' },
                h('thead', {}, h('tr', {}, h('th', {}, 'Subscription'), h('th', {}, 'Filter'), h('th', { class: 'num' }, 'Received'))),
                h(
                    'tbody',
                    {},
                    subs.map((s) =>
                        h(
                            'tr',
                            {},
                            h('td', { 'data-label': 'Subscription' }, subscriptionLabel(s.label)),
                            h('td', { class: 'muted', 'data-label': 'Filter' }, filterSummary(s.filter)),
                            h('td', { class: 'num', 'data-label': 'Received' }, (status.received[s.label] ?? 0).toLocaleString()),
                        ),
                    ),
                ),
            ),
        ),
    );
}

function subscriptionLabel(label) {
    const [kind, programId] = label.split(':');
    return programId ? `${kind} · ${state.watching?.programs[programId] ?? short(programId)}` : kind;
}

function filterSummary(filter) {
    const parts = [];
    const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;
    if (filter.programs) parts.push(plural(filter.programs.length, 'program'));
    if (filter.instructionNames) parts.push(plural(filter.instructionNames.length, 'instruction'));
    if (filter.accounts?.include) parts.push(plural(filter.accounts.include.length, 'account'));
    if (filter.includeFailed) parts.push('incl. failed');
    return parts.join(' · ');
}

const COVERAGE_TONE = { complete: 'ok', 'recent-only': 'sev-info', behind: 'sev-medium', failed: 'sev-high' };

function coverageCard(status) {
    const coverage = status?.coverage ?? [];
    if (coverage.length === 0) return null;
    return h(
        'section',
        { class: 'card' },
        h('header', { class: 'card-head' }, h('div', {}, h('div', { class: 'label' }, 'Coverage'), h('h2', {}, 'Parsed Events gap-fill'))),
        h(
            'div',
            { class: 'table-wrap' },
            h(
                'table',
                { class: 'responsive-table' },
                h(
                    'thead',
                    {},
                    h(
                        'tr',
                        {},
                        h('th', {}, 'Scan'),
                        h('th', { class: 'num' }, 'Scanned'),
                        h('th', { class: 'num' }, 'Matched'),
                        h('th', {}, 'Status'),
                        h('th', { class: 'num' }, 'Credits'),
                    ),
                ),
                h(
                    'tbody',
                    {},
                    coverage.map((c) =>
                        h(
                            'tr',
                            {},
                            h(
                                'td',
                                { 'data-label': 'Scan' },
                                c.plan.label,
                                c.coverage === 'complete' ? null : h('div', { class: 'muted small coverage-detail' }, c.summary.detail),
                            ),
                            h('td', { class: 'num', 'data-label': 'Scanned' }, c.progress.scannedTransactions.toLocaleString()),
                            h('td', { class: 'num', 'data-label': 'Matched' }, c.progress.matchedTransactions.toLocaleString()),
                            h(
                                'td',
                                { 'data-label': 'Status' },
                                h('span', { class: `sev ${COVERAGE_TONE[c.coverage]}`, title: c.summary.detail }, c.summary.label),
                            ),
                            h('td', { class: 'num', 'data-label': 'Credits' }, c.progress.creditsCharged),
                        ),
                    ),
                ),
            ),
        ),
    );
}

async function refreshReport() {
    try {
        await api('/api/report', {});
        state.reportRunning = true;
        render();
    } catch (error) {
        toast(error.message, true);
    }
}

function notConfigured() {
    return h(
        'section',
        { class: 'card stack' },
        h('div', {}, h('div', { class: 'label' }, 'Get started'), h('h2', {}, 'Watch a Solana program')),
        h(
            'p',
            { class: 'muted', style: 'max-width: 640px' },
            'Watchtower grades a program’s upgrade security and alerts on deployments, multisig changes, admin calls, treasury outflows and nonce setups, using Helius Parsed Events and Parsed Streams.',
        ),
        state.configError && state.apiKeySet ? h('p', { class: 'banner' }, state.configError) : null,
        !state.apiKeySet
            ? [
                  h('p', { class: 'banner' }, 'First, add your Helius API key to .env:'),
                  h('pre', { class: 'code' }, ENV_STEPS),
                  state.readOnly ? null : h('div', {}, h('button', { class: 'btn btn-outline', onclick: recheck }, 'Recheck')),
              ]
            : null,
        state.apiKeySet && !state.readOnly
            ? h('div', {}, h('button', { class: 'btn btn-brand', onclick: () => go('setup') }, 'Set up monitoring'))
            : null,
    );
}

function activityView() {
    const subjects = [...new Set(state.findings.map((f) => f.subjectLabel))].sort();
    const query = filters.search.toLowerCase();
    const shown = state.findings.filter(
        (f) =>
            severityRank(f.severity) >= severityRank(filters.minSeverity) &&
            (filters.subject === 'all' || f.subjectLabel === filters.subject) &&
            (!query || `${f.title} ${f.description} ${Object.values(f.details).join(' ')}`.toLowerCase().includes(query)),
    );
    const setFilter = (patch) => {
        Object.assign(filters, patch);
        render();
    };
    return [
        h(
            'section',
            { class: 'card stack' },
            h(
                'div',
                { class: 'section' },
                sectionTitle('Severity', 'and above'),
                h(
                    'div',
                    { class: 'chips' },
                    SEVERITIES.map((s) => chip(SEVERITY_LABEL[s], filters.minSeverity === s, () => setFilter({ minSeverity: s }))),
                ),
            ),
            subjects.length > 1
                ? h(
                      'div',
                      { class: 'section' },
                      sectionTitle('Subject'),
                      h(
                          'div',
                          { class: 'chips' },
                          chip('All', filters.subject === 'all', () => setFilter({ subject: 'all' })),
                          subjects.map((s) => chip(s, filters.subject === s, () => setFilter({ subject: s }))),
                      ),
                  )
                : null,
            h(
                'div',
                { class: 'section' },
                h('input', {
                    type: 'search',
                    placeholder: 'Search titles, addresses and details',
                    value: filters.search,
                    oninput: debounce((e) => (setFilter({ search: e.target.value }), focusSearch())),
                }),
            ),
        ),
        h(
            'section',
            { class: 'card' },
            h(
                'header',
                { class: 'card-head' },
                h(
                    'div',
                    {},
                    h('div', { class: 'label' }, 'Activity'),
                    h('h2', {}, `${shown.length} finding${shown.length === 1 ? '' : 's'}`),
                ),
            ),
            shown.length === 0 ? h('p', { class: 'empty' }, 'No findings match.') : h('ul', { class: 'feed' }, shown.map(feedItem)),
        ),
        h(
            'section',
            { class: 'card' },
            h('header', { class: 'card-head' }, h('div', {}, h('div', { class: 'label' }, 'Monitor'), h('h2', {}, 'Log'))),
            h('div', { class: 'log', id: 'log' }, logLines()),
        ),
    ];
}

function feedItem(f) {
    return h(
        'li',
        { class: `feed-item${fresh.has(f.id) ? ' fresh' : ''}` },
        h('div', {}, h('span', { class: `sev sev-${f.severity}` }, f.severity)),
        h(
            'div',
            { class: 'feed-body' },
            h('div', { class: 'feed-title' }, f.title),
            h('div', { class: 'feed-subject' }, f.subjectLabel),
            h('p', { class: 'feed-description' }, f.description),
            disclosure(
                `finding:${f.id}`,
                {},
                'Details',
                h(
                    'dl',
                    {},
                    Object.entries(f.details).map(([k, v]) => [h('dt', {}, k), h('dd', { class: 'mono' }, v)]),
                ),
            ),
        ),
        h(
            'div',
            { class: 'feed-meta' },
            h('span', {}, when(f)),
            h(
                'a',
                { class: 'mono', href: findingUrl(f), target: '_blank', rel: 'noopener' },
                f.signature ? `${f.signature.slice(0, 8)}…` : 'View',
            ),
        ),
    );
}

function logLines() {
    return state.logs
        .slice(-200)
        .map((entry) => h('div', { class: entry.level }, `${new Date(entry.time).toLocaleTimeString()}  ${entry.message}`));
}

function renderLog() {
    const log = document.getElementById('log');
    if (!log) return;
    const atBottom = log.scrollTop + log.clientHeight >= log.scrollHeight - 8;
    log.replaceChildren(...logLines());
    if (atBottom) log.scrollTop = log.scrollHeight;
}

function focusSearch() {
    const input = document.querySelector('input[type="search"]');
    input?.focus();
    input?.setSelectionRange(input.value.length, input.value.length);
}

function debounce(fn, ms = 200) {
    let timer;
    return (...args) => {
        clearTimeout(timer);
        timer = setTimeout(() => fn(...args), ms);
    };
}

function setupView() {
    if (state.readOnly) return [h('section', { class: 'card' }, h('p', {}, 'This Watchtower is read-only.'))];
    const loaded = !draft;
    if (loaded) {
        draft = clone({ ...DEFAULT_CONFIG, ...state.config });
        for (const key of ['programs', 'multisigs', 'mints', 'treasuries', 'watchedKeys']) draft[key] ??= [];
        draft.alerts ??= clone(DEFAULT_CONFIG.alerts);
        draft.backfill ??= clone(DEFAULT_CONFIG.backfill);
    }
    return [
        state.apiKeySet ? null : apiKeyCard(),
        h(
            'section',
            { class: 'card stack' },
            sectionTitle('Monitor', 'Each monitor has its own programs, alert channels and history, and runs on its own'),
            field(
                'Name',
                h('input', {
                    value: draft.name ?? '',
                    placeholder: draft.programs[0]?.name ?? 'e.g. Pump AMM',
                    maxlength: '60',
                    oninput: (e) => (draft.name = e.target.value.trim() || undefined),
                }),
            ),
        ),
        programsCard(),
        h(
            'section',
            { class: 'card stack' },
            addressSection('mints', 'Mints', 'Authority changes, large mints and Token-2022 extension updates', 'mint', EXAMPLE_MINTS),
            addressSection('multisigs', 'Additional multisigs', 'Upgrade multisigs are found automatically', 'multisig'),
            treasuriesSection(),
            addressSection(
                'watchedKeys',
                'Watched keys',
                'Protected from nonce setups and from signing away stake, token or account control. Authorities and multisig members get nonce protection automatically',
                null,
            ),
        ),
        alertsCard(),
        advancedCard(),
        saveBar(loaded),
    ];
}

/** Built after the sections, which fill in defaults on the draft, so a freshly loaded draft compares as unchanged. */
function saveBar(loaded) {
    if (loaded) savedDraft = JSON.stringify(draft);
    return h(
        'div',
        { class: 'save-bar', id: 'save-bar', hidden: !hasUnsavedChanges() },
        h('span', { class: 'save-status' }, 'Unsaved changes'),
        h('button', { class: 'btn btn-ghost', onclick: discardChanges }, 'Discard'),
        h('button', { class: 'btn btn-brand', onclick: save }, state.configured ? 'Save changes' : 'Save and start monitoring'),
    );
}

function hasUnsavedChanges() {
    return draft !== null && JSON.stringify(draft) !== savedDraft;
}

/** Inputs edit the draft without re-rendering, so the save bar is re-checked on every input. */
function updateSaveBar() {
    const bar = document.getElementById('save-bar');
    if (bar) bar.hidden = !hasUnsavedChanges();
}

function discardChanges() {
    draft = null;
    render();
}

function apiKeyCard() {
    return h(
        'section',
        { class: 'card stack' },
        sectionTitle('Helius API key', 'Read from .env, never entered in the browser'),
        h('pre', { class: 'code' }, ENV_STEPS),
        h('div', {}, h('button', { class: 'btn btn-outline', onclick: recheck }, 'Recheck')),
    );
}

async function recheck() {
    try {
        state = await api('/api/reload', {});
        toast(state.apiKeySet ? 'API key found' : 'Still no HELIUS_API_KEY in .env', !state.apiKeySet);
        render();
    } catch (error) {
        toast(error.message, true);
    }
}

function programsCard() {
    const preview = h('div');
    const idInput = h('input', { class: 'mono', placeholder: 'Program ID', autocomplete: 'off', spellcheck: 'false' });
    const nameInput = h('input', { placeholder: 'Name (optional)' });
    const discoverButton = h('button', { class: 'btn btn-primary', onclick: () => discover() }, 'Discover');

    async function discover() {
        discoverButton.disabled = true;
        discoverButton.textContent = 'Discovering…';
        preview.replaceChildren();
        try {
            const result = await api('/api/discover', { kind: 'program', address: idInput.value.trim() });
            preview.replaceChildren(programPreview(result, nameInput.value.trim()));
        } catch (error) {
            preview.replaceChildren(h('p', { class: 'error-text' }, error.message));
        } finally {
            discoverButton.disabled = false;
            discoverButton.textContent = 'Discover';
        }
    }

    const examples = h(
        'div',
        { class: 'chips' },
        EXAMPLE_PROGRAMS.map((p) =>
            chip(
                p.label,
                false,
                (e) => {
                    for (const other of e.currentTarget.parentElement.children) other.setAttribute('aria-pressed', 'false');
                    e.currentTarget.setAttribute('aria-pressed', 'true');
                    idInput.value = p.value;
                    nameInput.value = p.label;
                    discover();
                },
                p.value,
            ),
        ),
    );

    return h(
        'section',
        { class: 'card stack' },
        h(
            'div',
            { class: 'section' },
            sectionTitle('Programs', 'Discover finds the upgrade authority, its multisig, and suggests admin instructions from the IDL'),
            draft.programs.length ? h('div', { class: 'stack' }, draft.programs.map(programItem)) : null,
            h('div', { class: 'form-row' }, field('Program ID', idInput), field('Name', nameInput), discoverButton),
            examples,
            preview,
        ),
    );
}

function programPreview(p, name) {
    const authority = {
        immutable: 'Immutable: no key can change the code',
        wallet: `Single wallet ${p.upgradeAuthority}`,
        squads: p.multisig
            ? `Squads v${p.multisig.version} · ${p.multisig.threshold} of ${p.multisig.members.length}${p.multisig.version === 4 ? ` · time lock ${p.multisig.timeLockSeconds}s` : ' · no time lock'}`
            : '',
        'unknown-pda': `PDA ${p.upgradeAuthority} (not a Squads vault)`,
    }[p.authorityKind];
    const selected = new Set(p.idl?.privileged ?? []);
    const chips = h('div', { class: 'chips chip-scroll' });
    const drawChips = () =>
        chips.replaceChildren(
            ...(p.idl?.instructions ?? []).map((ix) =>
                chip(ix, selected.has(ix), () => {
                    if (selected.has(ix)) selected.delete(ix);
                    else selected.add(ix);
                    drawChips();
                }),
            ),
        );
    drawChips();
    return h(
        'div',
        { class: 'preview' },
        h(
            'dl',
            {},
            h('dt', {}, 'Upgrade authority'),
            h('dd', {}, authority),
            h('dt', {}, 'Program data'),
            h('dd', { class: 'mono' }, p.programData),
            p.multisig ? [h('dt', {}, 'Multisig'), h('dd', { class: 'mono' }, p.multisig.address)] : null,
            h('dt', {}, 'IDL'),
            h('dd', {}, p.idl ? `${p.idl.instructions.length} instructions` : 'Not published'),
        ),
        p.idl
            ? h(
                  'div',
                  { class: 'stack', style: 'gap: 8px' },
                  sectionTitle('Admin-only instructions', 'Suggested ones are selected; click to toggle'),
                  chips,
              )
            : null,
        h(
            'div',
            {},
            h(
                'button',
                {
                    class: 'btn btn-primary',
                    onclick: () => {
                        draft.programs = draft.programs.filter((existing) => existing.id !== p.programId);
                        draft.programs.push({ id: p.programId, ...(name ? { name } : {}), privilegedInstructions: [...selected] });
                        render();
                    },
                },
                'Add program',
            ),
        ),
    );
}

function listItem(title, address, onRemove, ...body) {
    return h(
        'div',
        { class: 'list-item' },
        h(
            'div',
            { class: 'list-item-head' },
            h(
                'div',
                { class: 'list-item-name' },
                h('span', { class: 'title' }, title),
                address ? [' ', h('span', { class: 'mono muted' }, address)] : null,
            ),
            h('button', { class: 'btn btn-ghost btn-sm', onclick: () => (onRemove(), render()) }, 'Remove'),
        ),
        ...body,
    );
}

function programItem(program, index) {
    return listItem(
        program.name ?? short(program.id),
        program.id,
        () => draft.programs.splice(index, 1),
        program.privilegedInstructions?.length
            ? h(
                  'div',
                  { class: 'chips' },
                  program.privilegedInstructions.map((ix, i) => tag(ix, () => (program.privilegedInstructions.splice(i, 1), render()))),
              )
            : h('span', { class: 'muted small' }, 'No admin instructions watched'),
        h(
            'label',
            {
                class: 'checkbox',
                title: 'Finds the addresses that pay out this program’s funds, prices them with the Helius DAS API, and alerts when 20% of a holding leaves at once. For lending and perps protocols, not routers.',
            },
            h('input', {
                type: 'checkbox',
                checked: program.watchVaults ?? false,
                onchange: (e) => (program.watchVaults = e.target.checked),
            }),
            'Watch its vaults (lending, perps)',
        ),
    );
}

function addressSection(key, title, hint, discoverKind, examples = []) {
    const address = h('input', { class: 'mono', placeholder: 'Address', autocomplete: 'off', spellcheck: 'false' });
    const label = h('input', { placeholder: 'Label (optional)' });
    const message = h('div');
    const add = async () => {
        const value = address.value.trim();
        message.replaceChildren();
        try {
            if (discoverKind) {
                const found = await api('/api/discover', { kind: discoverKind, address: value });
                if (discoverKind === 'multisig') toast(`Squads v${found.version} · ${found.threshold} of ${found.members.length}`);
            } else if (!BASE58.test(value)) {
                throw new Error('Enter a base58 address');
            }
            draft[key] = draft[key].filter((item) => item.address !== value);
            draft[key].push({ address: value, ...(label.value.trim() ? { label: label.value.trim() } : {}) });
            render();
        } catch (error) {
            message.replaceChildren(h('p', { class: 'error-text' }, error.message));
        }
    };
    const present = new Set(draft[key].map((item) => item.address));
    return h(
        'div',
        { class: 'section' },
        sectionTitle(title, hint),
        draft[key].length
            ? h(
                  'div',
                  { class: 'stack', style: 'gap: 8px' },
                  draft[key].map((item, i) => listItem(item.label ?? short(item.address), item.address, () => draft[key].splice(i, 1))),
              )
            : null,
        h(
            'div',
            { class: 'form-row' },
            field('Address', address),
            field('Label', label),
            h('button', { class: 'btn btn-outline', onclick: add }, 'Add'),
        ),
        examples.length
            ? h(
                  'div',
                  { class: 'chips' },
                  examples.map((ex) =>
                      chip(
                          ex.label,
                          present.has(ex.value),
                          () => {
                              address.value = ex.value;
                              label.value = ex.label;
                              add();
                          },
                          ex.value,
                      ),
                  ),
              )
            : null,
        message,
    );
}

function treasuriesSection() {
    const address = h('input', { class: 'mono', placeholder: 'Treasury address', autocomplete: 'off', spellcheck: 'false' });
    const label = h('input', { placeholder: 'Label (optional)' });
    const sol = h('input', { type: 'number', min: '0', placeholder: 'e.g. 500' });
    const add = () => {
        const value = address.value.trim();
        if (!BASE58.test(value)) return toast('Enter a base58 treasury address', true);
        draft.treasuries.push({
            address: value,
            ...(label.value.trim() ? { label: label.value.trim() } : {}),
            thresholds: sol.value ? { SOL: Number(sol.value) } : {},
            windowMinutes: 60,
            alertOnAnyOutflow: false,
        });
        render();
    };
    return h(
        'div',
        { class: 'section' },
        sectionTitle('Treasuries', 'One outflow at a threshold is high; 3× within an hour, or 3 assets leaving, is critical'),
        draft.treasuries.map(treasuryItem),
        h(
            'div',
            { class: 'form-row three' },
            field('Address', address),
            field('Label', label),
            field('SOL threshold', sol),
            h('button', { class: 'btn btn-outline', onclick: add }, 'Add'),
        ),
    );
}

function treasuryItem(treasury, index) {
    treasury.thresholds ??= {};
    treasury.allowedDestinations ??= [];
    const mint = h('input', { class: 'mono grow', placeholder: 'Token mint' });
    const amount = h('input', { type: 'number', min: '0', placeholder: 'Threshold', class: 'amount' });
    const destination = h('input', {
        class: 'mono grow',
        placeholder: 'Allowed destination (optional)',
        autocomplete: 'off',
        spellcheck: 'false',
    });
    const addDestination = () => {
        const value = destination.value.trim();
        if (!BASE58.test(value)) return toast('Enter a base58 address', true);
        if (!treasury.allowedDestinations.includes(value)) treasury.allowedDestinations.push(value);
        render();
    };
    return listItem(
        treasury.label ?? short(treasury.address),
        treasury.address,
        () => draft.treasuries.splice(index, 1),
        h(
            'div',
            { class: 'chips' },
            Object.entries(treasury.thresholds).map(([asset, value]) =>
                tag(
                    `${asset === 'SOL' ? 'SOL' : short(asset)} ≥ ${value.toLocaleString()}`,
                    () => (delete treasury.thresholds[asset], render()),
                ),
            ),
        ),
        h(
            'div',
            { class: 'row field-row' },
            mint,
            amount,
            h(
                'button',
                {
                    class: 'btn btn-outline btn-sm',
                    onclick: () =>
                        mint.value.trim() && amount.value
                            ? ((treasury.thresholds[mint.value.trim()] = Number(amount.value)), render())
                            : toast('Enter a mint and a threshold', true),
                },
                'Add token threshold',
            ),
            h(
                'label',
                { class: 'checkbox' },
                h('input', {
                    type: 'checkbox',
                    checked: treasury.alertOnAnyOutflow,
                    onchange: (e) => (treasury.alertOnAnyOutflow = e.target.checked),
                }),
                'Alert on any outflow',
            ),
        ),
        treasury.allowedDestinations.length
            ? h(
                  'div',
                  { class: 'chips' },
                  treasury.allowedDestinations.map((d, i) =>
                      tag(`to ${short(d)}`, () => (treasury.allowedDestinations.splice(i, 1), render())),
                  ),
              )
            : null,
        h(
            'div',
            { class: 'row field-row' },
            destination,
            h(
                'button',
                { class: 'btn btn-outline btn-sm', onclick: addDestination, title: 'Once any are listed, an outflow anywhere else alerts' },
                'Add allowed destination',
            ),
        ),
    );
}

function alertsCard() {
    const channels = draft.alerts.sinks.filter((s) => s.type !== 'console');
    const severitySelect = (value, onChange, suffix = '') =>
        h(
            'select',
            { onchange: (e) => onChange(e.target.value) },
            SEVERITIES.map((s) => h('option', { value: s, selected: s === value || undefined }, `${SEVERITY_LABEL[s]}${suffix}`)),
        );
    return h(
        'section',
        { class: 'card stack' },
        h(
            'div',
            { class: 'section' },
            sectionTitle('Alerts', 'The terminal always gets alerts; secrets are stored in .env'),
            h(
                'label',
                { class: 'field compact-field' },
                'Minimum severity',
                severitySelect(draft.alerts.minSeverity, (v) => (draft.alerts.minSeverity = v)),
            ),
        ),
        h(
            'div',
            { class: 'section' },
            sectionTitle('Channels', 'Pick one to add it'),
            choiceCards(CHANNELS, (id) => {
                draft.alerts.sinks.push({ type: id, minSeverity: 'medium' });
                render();
            }),
            channels.map((sink) => {
                const channel = CHANNELS.find((c) => c.id === sink.type);
                return listItem(
                    channel.title,
                    null,
                    () => (draft.alerts.sinks = draft.alerts.sinks.filter((s) => s !== sink)),
                    h(
                        'div',
                        { class: 'row field-row' },
                        channel.fields.map(([key, placeholder]) =>
                            h('input', {
                                class: 'mono grow',
                                placeholder,
                                value: sink[key] ?? '',
                                oninput: (e) => (sink[key] = e.target.value.trim()),
                            }),
                        ),
                        severitySelect(sink.minSeverity ?? 'medium', (v) => (sink.minSeverity = v), ' and up'),
                    ),
                );
            }),
            state.configured
                ? h(
                      'div',
                      {},
                      h(
                          'button',
                          { class: 'btn btn-outline btn-sm', onclick: testAlert, title: 'Sends to the channels in the saved config' },
                          'Send test alert',
                      ),
                  )
                : null,
        ),
    );
}

function advancedCard() {
    const number = (label, get, set) =>
        field(label, h('input', { type: 'number', min: '1', value: get(), oninput: (e) => set(Number(e.target.value)) }));
    return h(
        'section',
        { class: 'card stack' },
        h(
            'div',
            { class: 'section' },
            sectionTitle('Advanced'),
            h(
                'div',
                { class: 'grid-3' },
                number(
                    'Lookback days for the first scan',
                    () => draft.backfill.lookbackDays,
                    (v) => (draft.backfill.lookbackDays = v),
                ),
                number(
                    'Max transactions per scan',
                    () => draft.backfill.maxScannedTransactions,
                    (v) => (draft.backfill.maxScannedTransactions = v),
                ),
                number(
                    'IDL check interval (minutes)',
                    () => draft.idlPollMinutes ?? 10,
                    (v) => (draft.idlPollMinutes = v),
                ),
            ),
        ),
    );
}

async function save() {
    if (draft.programs.length === 0) return toast('Add at least one program', true);
    if (!state.apiKeySet) return toast('Add HELIUS_API_KEY to .env first, then click Recheck', true);
    try {
        state = await api('/api/config', { config: draft });
        draft = null;
        toast('Saved. Monitoring is starting.');
        go('overview');
    } catch (error) {
        toast(error.message, true);
    }
}

async function testAlert() {
    try {
        const result = await api('/api/test-alert', {});
        toast(
            result.delivered ? `Test alert sent to ${result.sinks.join(', ')}` : 'A channel rejected the test alert; see the log',
            !result.delivered,
        );
    } catch (error) {
        toast(error.message, true);
    }
}

boot().catch((error) => {
    document.body.classList.add('ready');
    document
        .getElementById('view')
        .replaceChildren(h('section', { class: 'card' }, h('p', { class: 'error-text' }, `Could not load Watchtower: ${error.message}`)));
});
