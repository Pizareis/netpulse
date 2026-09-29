'use strict';

const $ = (sel) => document.querySelector(sel);
const MAX_POINTS = 300;
const state = { info: null, devices: [], alerts: [], traffic: [] };

// ---------- formatting ----------
function rate(bps) {
  const units = ['B/s', 'KB/s', 'MB/s', 'GB/s'];
  let i = 0;
  while (bps >= 1024 && i < units.length - 1) { bps /= 1024; i++; }
  return `${bps.toFixed(bps < 10 && i > 0 ? 1 : 0)} ${units[i]}`;
}
function ago(ts) {
  const s = Math.max(0, (Date.now() - new Date(ts)) / 1000);
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
function clock(ts) { return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }); }
function esc(s) { return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]); }
function ipKey(ip) { return ip.split('.').reduce((a, o) => a * 256 + Number(o), 0); }

// ---------- rendering ----------
function renderInfo() {
  const i = state.info;
  if (!i) return;
  $('#netinfo').innerHTML = [
    ['iface', i.iface], ['ip', i.ip], ['subnet', i.subnet], ['gateway', i.gateway || '?'],
  ].map(([k, v]) => `<span>${k} <b>${esc(v)}</b></span>`).join('');
  const ports = (i.tripwire_ports || []).join(', ') || 'none';
  $('#footer').textContent = `Honeypot ports: ${ports} · running since ${new Date(i.started).toLocaleString()}`;
  setScanning(i.scanning);
}

function renderKPIs() {
  const online = state.devices.filter((d) => d.online).length;
  $('#kOnline').textContent = online;
  $('#kTotal').textContent = `${state.devices.length} known`;
  const last = state.traffic[state.traffic.length - 1];
  $('#kRx').textContent = last ? rate(last.rx) : '-';
  $('#kTx').textContent = last ? rate(last.tx) : '-';
  if (state.traffic.length) {
    $('#kRxPeak').textContent = `peak ${rate(Math.max(...state.traffic.map((s) => s.rx)))}`;
    $('#kTxPeak').textContent = `peak ${rate(Math.max(...state.traffic.map((s) => s.tx)))}`;
  }
  if (state.info) {
    $('#kAlerts').textContent = state.info.alerts_24h;
    $('#kCritical').textContent = `${state.info.critical_24h} critical`;
    $('#kCritical').style.color = state.info.critical_24h ? 'var(--crit)' : '';
  }
}

function renderDevices() {
  const rows = [...state.devices].sort((a, b) => (b.online - a.online) || ipKey(a.ip) - ipKey(b.ip));
  const hour = 3600 * 1000;
  const started = state.info ? new Date(state.info.started).getTime() : 0;
  // "new" = joined within the last hour, excluding the startup baseline scan.
  const isNew = (d) => {
    const first = new Date(d.first_seen).getTime();
    return !d.self && Date.now() - first < hour && first - started > 30000;
  };
  $('#devices').innerHTML = rows.map((d) => {
    const tags = [
      d.gateway ? '<span class="tag gw">gateway</span>' : '',
      d.self ? '<span class="tag self">this pc</span>' : '',
      isNew(d) ? '<span class="tag new">new</span>' : '',
    ].join('');
    return `<tr class="${d.online ? '' : 'offline'}">
      <td><span class="dot ${d.online ? 'on' : ''}" title="${d.online ? 'online' : 'offline'}"></span></td>
      <td class="mono">${esc(d.ip)}${tags}</td>
      <td class="mono">${esc(d.mac)}</td>
      <td>${esc(d.vendor) || '<span class="muted">unknown</span>'}</td>
      <td>${esc(d.hostname) || '<span class="muted">-</span>'}</td>
      <td class="muted">${ago(d.first_seen)}</td>
      <td class="muted">${ago(d.last_seen)}</td>
    </tr>`;
  }).join('') || '<tr><td colspan="7" class="muted">Scanning the network…</td></tr>';
}

function alertItem(a) {
  return `<li class="${esc(a.severity)}"><span class="ts">${clock(a.time)}</span>
    <div class="t">${esc(a.title)}</div><div class="d">${esc(a.detail)}</div></li>`;
}
function renderAlerts() {
  $('#alerts').innerHTML = state.alerts.map(alertItem).join('') || '<li class="empty">No alerts yet. All quiet.</li>';
}

function toast(a) {
  const el = document.createElement('div');
  el.className = `toast ${a.severity}`;
  el.innerHTML = `<div class="t">${esc(a.title)}</div><div class="d">${esc(a.detail)}</div>`;
  $('#toasts').appendChild(el);
  setTimeout(() => el.remove(), 7000);
}

function setScanning(on) {
  $('#scanBtn').disabled = on;
  $('#scanBtn').textContent = on ? 'Scanning…' : 'Scan now';
  const last = state.info?.last_scan;
  $('#scanState').textContent = on ? 'sweeping subnet…'
    : last && !last.startsWith('0001') ? `last scan ${ago(last)}` : '';
}

// ---------- chart (plain canvas, no dependencies) ----------
function niceMax(v) {
  if (v <= 0) return 1024;
  const p = Math.pow(1024, Math.floor(Math.log(v) / Math.log(1024)));
  const n = v / p;
  const step = [1, 2, 5, 10, 20, 50, 100, 200, 500, 1000].find((s) => s >= n);
  return step * p;
}

function drawChart() {
  const canvas = $('#chart');
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth, h = canvas.clientHeight;
  if (canvas.width !== w * dpr || canvas.height !== h * dpr) { canvas.width = w * dpr; canvas.height = h * dpr; }
  const ctx = canvas.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);

  const css = getComputedStyle(document.documentElement);
  const pad = { l: 68, r: 8, t: 8, b: 22 };
  const pw = w - pad.l - pad.r, ph = h - pad.t - pad.b;
  const data = state.traffic;
  const max = niceMax(Math.max(1, ...data.map((s) => Math.max(s.rx, s.tx))));

  ctx.font = '11px ' + css.getPropertyValue('--mono');
  ctx.strokeStyle = css.getPropertyValue('--line');
  ctx.fillStyle = css.getPropertyValue('--muted');
  ctx.lineWidth = 1;
  ctx.textAlign = 'right';
  ctx.textBaseline = 'middle';
  for (let i = 0; i <= 4; i++) {
    const y = pad.t + ph - (ph * i) / 4;
    ctx.beginPath(); ctx.moveTo(pad.l, y + .5); ctx.lineTo(w - pad.r, y + .5); ctx.stroke();
    ctx.fillText(rate((max * i) / 4), pad.l - 8, y);
  }
  ctx.textAlign = 'center';
  ctx.textBaseline = 'top';
  ['-5m', '-4m', '-3m', '-2m', '-1m', 'now'].forEach((lbl, i) => ctx.fillText(lbl, pad.l + (pw * i) / 5, h - pad.b + 6));
  if (data.length < 2) return;

  const now = Date.now();
  const x = (t) => pad.l + pw - ((now - new Date(t)) / (MAX_POINTS * 1000)) * pw;
  const y = (v) => pad.t + ph - (v / max) * ph;
  for (const [key, color] of [['rx', '--rx'], ['tx', '--tx']]) {
    const c = css.getPropertyValue(color).trim();
    ctx.beginPath();
    data.forEach((s, i) => (i ? ctx.lineTo(x(s.t), y(s[key])) : ctx.moveTo(x(s.t), y(s[key]))));
    ctx.strokeStyle = c; ctx.lineWidth = 2; ctx.lineJoin = 'round'; ctx.stroke();
    ctx.lineTo(x(data[data.length - 1].t), pad.t + ph);
    ctx.lineTo(x(data[0].t), pad.t + ph);
    ctx.closePath();
    const g = ctx.createLinearGradient(0, pad.t, 0, pad.t + ph);
    g.addColorStop(0, c + '55'); g.addColorStop(1, c + '00');
    ctx.fillStyle = g; ctx.fill();
  }
}

// ---------- data ----------
async function getJSON(url) { const r = await fetch(url); return r.json(); }

async function refreshInfo() { state.info = await getJSON('/api/info'); renderInfo(); renderKPIs(); }

function connect() {
  const es = new EventSource('/api/events');
  const live = $('#live');
  es.onopen = () => { live.className = 'live on'; live.textContent = 'live'; };
  es.onerror = () => { live.className = 'live off'; live.textContent = 'reconnecting'; };
  es.addEventListener('traffic', (e) => {
    state.traffic.push(JSON.parse(e.data));
    if (state.traffic.length > MAX_POINTS) state.traffic.shift();
    renderKPIs(); drawChart();
  });
  es.addEventListener('devices', (e) => { state.devices = JSON.parse(e.data); renderDevices(); renderKPIs(); });
  es.addEventListener('alert', (e) => {
    const a = JSON.parse(e.data);
    state.alerts.unshift(a);
    state.alerts.length = Math.min(state.alerts.length, 100);
    if (state.info) { state.info.alerts_24h++; if (a.severity === 'critical') state.info.critical_24h++; }
    renderAlerts(); renderKPIs(); toast(a);
  });
  es.addEventListener('scan', (e) => {
    const s = JSON.parse(e.data);
    if (s.state === 'started') setScanning(true); else refreshInfo();
  });
}

async function init() {
  const [info, devices, alerts, traffic] = await Promise.all(
    ['/api/info', '/api/devices', '/api/alerts', '/api/traffic'].map(getJSON));
  Object.assign(state, { info, devices: devices || [], alerts: alerts || [], traffic: traffic || [] });
  renderInfo(); renderKPIs(); renderDevices(); renderAlerts(); drawChart();
  connect();
  $('#scanBtn').addEventListener('click', () => { setScanning(true); fetch('/api/scan', { method: 'POST' }); });
  window.addEventListener('resize', drawChart);
  setInterval(() => { renderDevices(); setScanning(state.info?.scanning && $('#scanBtn').disabled); }, 10000);
}

init();
