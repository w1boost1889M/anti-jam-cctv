# =============================================================================
# Anti-Jam CCTV Protection System
# =============================================================================
# Copyright (C) 2026 w1boost1889M (https://github.com/w1boost1889M)
#
# This file is part of Anti-Jam CCTV Protection System.
#
# Anti-Jam CCTV Protection System is free software: you can redistribute it
# and/or modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation, either version 3 of the License,
# or (at your option) any later version.
#
# Anti-Jam CCTV Protection System is distributed in the hope that it will be
# useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
# Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program. If not, see <https://www.gnu.org/licenses/>.
#
# Author   : Avoceous
# GitHub   : https://github.com/Avoceous
# Project  : https://github.com/Avoceous/anti-jam-cctv
# License  : GNU General Public License v3.0 (GPL-3.0)
# Created  : April 2026
# File     : dashboard/web_ui.py
# =============================================================================
"""
web_ui.py — Real-Time Web Dashboard
=====================================
Accessible at http://<host>:8888/

Displays:
  - Live jamming detection status & threat confidence
  - Network mode (WiFi / 4G-LTE / Local)
  - Per-camera health and recording status
  - Recent alert timeline
  - System uptime and RSSI
"""

import asyncio
import logging
import time
from threading import Thread

log = logging.getLogger("Dashboard")

try:
    from flask import Flask, jsonify, render_template_string
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    log.warning("Flask not installed — dashboard disabled. Run: pip install flask")

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>🛡️ Anti-Jam CCTV — Avoceous</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', sans-serif; background: #0a0f1e; color: #e0e8ff; }
  .header { background: #111827; padding: 16px 24px; border-bottom: 2px solid #1e3a5f;
            display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px; }
  .header h1 { font-size: 1.4rem; }
  .header-sub { font-size: 0.72rem; color: #6b7280; }
  .header-sub a { color: #60a5fa; text-decoration: none; }
  .badge { padding: 4px 12px; border-radius: 20px; font-size: 0.75rem; font-weight: bold; }
  .badge-ok    { background: #064e3b; color: #6ee7b7; }
  .badge-warn  { background: #78350f; color: #fcd34d; }
  .badge-alert { background: #7f1d1d; color: #fca5a5; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
          gap: 16px; padding: 20px; }
  .card { background: #111827; border-radius: 12px; padding: 20px;
          border: 1px solid #1e3a5f; }
  .card h2 { font-size: 0.85rem; text-transform: uppercase; color: #6b7280;
             margin-bottom: 12px; letter-spacing: 1px; }
  .network-mode { font-size: 1.5rem; font-weight: bold; }
  .wifi-mode  { color: #10b981; }
  .lte-mode   { color: #f59e0b; }
  .local-mode { color: #ef4444; }
  .status-row { display: flex; justify-content: space-between; align-items: center;
                padding: 8px 0; border-bottom: 1px solid #1e3a5f; }
  .status-row:last-child { border-bottom: none; }
  .dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; margin-right: 8px; }
  .dot-green  { background: #10b981; box-shadow: 0 0 6px #10b981; }
  .dot-red    { background: #ef4444; box-shadow: 0 0 6px #ef4444; animation: pulse 1s infinite; }
  .dot-yellow { background: #f59e0b; box-shadow: 0 0 6px #f59e0b; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
  .jam-item { background: #1f2937; border-left: 3px solid #ef4444;
              border-radius: 4px; padding: 10px; margin-bottom: 8px; font-size: 0.82rem; }
  .jam-item .conf { color: #f59e0b; font-weight: bold; }
  .conf-bar { height: 6px; border-radius: 3px; background: #374151; margin-top: 6px; }
  .conf-fill { height: 100%; border-radius: 3px; background: linear-gradient(90deg, #f59e0b, #ef4444); }
  footer { text-align: center; padding: 20px; color: #374151; font-size: 0.75rem; }
  footer a { color: #60a5fa; text-decoration: none; }

/* ===========================
   Mobile Responsive
   =========================== */

@media (max-width: 1024px) {

    .grid{
        grid-template-columns:1fr;
    }

    .card{
        padding:18px;
    }

}

@media (max-width:768px){

    body{
        font-size:15px;
    }

    .header{
        flex-direction:column;
        align-items:flex-start;
        padding:18px;
    }

    .header h1{
        font-size:1.2rem;
        word-break:break-word;
    }

    .header-sub{
        font-size:.8rem;
    }

    .badge{
        margin-top:10px;
    }

    .grid{
        padding:14px;
        gap:14px;
        grid-template-columns:1fr;
    }

    .card{
        padding:16px;
        border-radius:10px;
    }

    .card h2{
        font-size:.8rem;
    }

    .network-mode{
        font-size:1.2rem;
    }

    .status-row{
        flex-direction:column;
        align-items:flex-start;
        gap:8px;
    }

    .jam-item{
        font-size:.9rem;
    }

}

@media (max-width:480px){

    body{
        font-size:14px;
    }

    .header{
        padding:14px;
    }

    .header h1{
        font-size:1rem;
    }

    .grid{
        padding:10px;
        gap:10px;
    }

    .card{
        padding:14px;
    }

    .network-mode{
        font-size:1rem;
    }

    .badge{
        width:100%;
        text-align:center;
    }

    .status-row{
        padding:12px 0;
    }

    .jam-item{
        padding:12px;
    }

    footer{
        padding:16px;
        font-size:.7rem;
    }

}
  
</style>
</head>
<body>

<div class="header">
  <div>
    <h1>🛡️ Anti-Jam CCTV Protection System</h1>
    <div class="header-sub">
      Copyright &copy; 2026 <a href="https://github.com/Avoceous" target="_blank">Avoceous</a>
      &nbsp;|&nbsp;
      <a href="https://github.com/Avoceous/anti-jam-cctv" target="_blank">github.com/Avoceous/anti-jam-cctv</a>
      &nbsp;|&nbsp; GPL-3.0 License
    </div>
  </div>
  <span id="topBadge" class="badge badge-ok">MONITORING</span>
</div>

<div class="grid">

  <!-- Network Mode -->
  <div class="card">
    <h2>Network Mode</h2>
    <div class="network-mode wifi-mode" id="netMode">—</div>
    <div style="font-size:0.75rem;color:#6b7280;margin-top:4px" id="netSince">Loading...</div>
    <div style="margin-top:12px">
      <div class="status-row"><span>Jam Events Total</span><strong id="jamCount">0</strong></div>
      <div class="status-row"><span>Failover Count</span><strong id="failoverCount">0</strong></div>
      <div class="status-row"><span>Local Recording</span><strong id="localRec">No</strong></div>
    </div>
  </div>

  <!-- Active Jams -->
  <div class="card">
    <h2>🚨 Active Jamming Events</h2>
    <div id="jamList"><div style="color:#10b981">✅ No active threats detected</div></div>
  </div>

  <!-- Camera Status -->
  <div class="card">
    <h2>📹 Camera Health</h2>
    <div id="cameraList"><div style="color:#6b7280">No cameras configured</div></div>
  </div>

  <!-- System Info -->
  <div class="card">
    <h2>System Info</h2>
    <div class="status-row"><span>Uptime</span><strong id="uptime">—</strong></div>
    <div class="status-row"><span>RSSI</span><strong id="rssi">—</strong></div>
    <div class="status-row"><span>Known APs</span><strong id="knownAPs">—</strong></div>
    <div class="status-row"><span>Deauth Count</span><strong id="deauthCount">0</strong></div>
    <div class="status-row"><span>Last Update</span><strong id="lastUpdate">—</strong></div>
  </div>

</div>

<footer>
  Anti-Jam CCTV v1.0 &nbsp;|&nbsp;
  Copyright &copy; 2026 <a href="https://github.com/Avoceous" target="_blank">Avoceous</a>
  &nbsp;|&nbsp;
  <a href="https://github.com/Avoceous/anti-jam-cctv" target="_blank">github.com/Avoceous/anti-jam-cctv</a>
  &nbsp;|&nbsp; Licensed under GNU GPL v3.0
</footer>

<script>
const START = Date.now();

function fmt(ts) {
  return ts ? new Date(ts * 1000).toLocaleTimeString() : '—';
}
function fmtUptime(ms) {
  let s=Math.floor(ms/1000), m=Math.floor(s/60), h=Math.floor(m/60);
  return `${h}h ${m%60}m ${s%60}s`;
}

async function refresh() {
  try {
    const r = await fetch('/api/status');
    const d = await r.json();
    const fs  = d.failover  || {};
    const det = d.detector  || {};
    const cams= d.cameras   || [];

    // Network mode
    const mode = fs.network_mode || 'wifi';
    const el   = document.getElementById('netMode');
    el.textContent = mode.toUpperCase();
    el.className   = 'network-mode ' + (
      mode==='wifi' ? 'wifi-mode' : mode.includes('lte') ? 'lte-mode' : 'local-mode'
    );
    document.getElementById('jamCount').textContent     = fs.jam_event_count  || 0;
    document.getElementById('failoverCount').textContent= fs.recovery_attempts || 0;
    document.getElementById('localRec').textContent     = fs.local_recording   ? 'YES 🔴' : 'No';
    document.getElementById('netSince').textContent     = fs.last_failover
      ? 'Last failover: ' + fmt(fs.last_failover)
      : 'Primary network stable';

    // Active jams
    const jams    = det.active_jams || {};
    const jamKeys = Object.keys(jams);
    const topBadge= document.getElementById('topBadge');

    if (jamKeys.length > 0) {
      topBadge.className   = 'badge badge-alert';
      topBadge.textContent = '🚨 JAM DETECTED';
      document.getElementById('jamList').innerHTML = jamKeys.map(k => {
        const j   = jams[k];
        const pct = Math.round(j.confidence * 100);
        return `<div class="jam-item">
          <strong>${k.replace(/_/g,' ').toUpperCase()}</strong>
          <span class="conf"> ${pct}% confidence</span><br>
          <small>${j.details}</small><br>
          <small style="color:#6b7280">${fmt(j.timestamp)}</small>
          <div class="conf-bar"><div class="conf-fill" style="width:${pct}%"></div></div>
        </div>`;
      }).join('');
    } else {
      topBadge.className   = 'badge badge-ok';
      topBadge.textContent = 'MONITORING';
      document.getElementById('jamList').innerHTML =
        '<div style="color:#10b981">✅ No active threats detected</div>';
    }

    // Cameras
    document.getElementById('cameraList').innerHTML = cams.length
      ? cams.map(c => `
        <div class="status-row">
          <span>
            <span class="dot ${c.healthy ? 'dot-green' : 'dot-red'}"></span>${c.name}
          </span>
          <span style="font-size:0.8rem">
            ${c.healthy ? '🟢 LIVE' : (c.recording_locally ? '📼 LOCAL REC' : '🔴 OFFLINE')}
          </span>
        </div>`).join('')
      : '<div style="color:#6b7280">No cameras configured</div>';

    // System
    document.getElementById('rssi').textContent       = det.rssi_current ? det.rssi_current + ' dBm' : '—';
    document.getElementById('knownAPs').textContent   = det.known_aps   || 0;
    document.getElementById('deauthCount').textContent= det.deauth_count_last_interval || 0;
    document.getElementById('uptime').textContent     = fmtUptime(Date.now() - START);
    document.getElementById('lastUpdate').textContent = new Date().toLocaleTimeString();

  } catch(e) { console.error(e); }
}

refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>
"""


class DashboardServer:
    def __init__(self, config: dict, jam_detector, stream_monitor, failover_manager):
        self.cfg      = config
        self.detector = jam_detector
        self.streams  = stream_monitor
        self.failover = failover_manager
        self._start   = time.time()
        self.port     = config.get('port', 8888)
        self.host     = config.get('host', '0.0.0.0')

    async def run(self):
        if not FLASK_AVAILABLE:
            log.warning("Flask not available — dashboard disabled")
            return

        app = Flask(__name__)

        @app.route('/')
        def index():
            return render_template_string(DASHBOARD_HTML)

        @app.route('/api/status')
        def status():
            return jsonify({
                "detector": self.detector.get_status(),
                "failover": self.failover.get_status(),
                "cameras":  self.streams.get_status(),
                "uptime":   time.time() - self._start,
            })

        thread = Thread(
            target=lambda: app.run(
                host=self.host, port=self.port,
                debug=False, use_reloader=False
            ),
            daemon=True
        )
        thread.start()
        log.info(f"🌐 Dashboard: http://{self.host}:{self.port}/")

        while True:
            await asyncio.sleep(60)

    async def stop(self):
        pass

# =============================================================================
# End of file: dashboard/web_ui.py
# Copyright (C) 2026 Avoceous (https://github.com/Avoceous)
# Licensed under GNU General Public License v3.0 (GPL-3.0)
# https://github.com/Avoceous/anti-jam-cctv
# =============================================================================
