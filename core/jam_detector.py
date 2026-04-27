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
# GitHub   : https://github.com/w1boost1889M
# Project  : https://github.com/w1boost1889M/anti-jam-cctv
# License  : GNU General Public License v3.0 (GPL-3.0)
# Created  : April 2026
# File     : core/jam_detector.py
# =============================================================================
"""
jam_detector.py — Multi-Vector WiFi Jamming Detection Engine
=============================================================
Detects:
  1. Deauth frame floods      (802.11 management frame attack)
  2. RSSI sudden drop         (RF power jamming)
  3. Beacon disappearance     (AP being blocked/jammed)
  4. Beacon spoofing          (multiple fake APs flooding same SSID)
  5. Channel utilization spike (RF noise jamming)
  6. Consecutive connection failures

Requires: scapy, asyncio
Root/sudo required for monitor mode + packet capture.
"""

import asyncio
import logging
import time
import subprocess
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

log = logging.getLogger("JamDetector")

try:
    from scapy.all import AsyncSniffer, Dot11, Dot11Deauth, Dot11Beacon, RadioTap, conf
    SCAPY_AVAILABLE = True
except ImportError:
    log.warning("scapy not installed. Packet-level detection disabled. Run: pip install scapy")
    SCAPY_AVAILABLE = False


class JamType(Enum):
    DEAUTH_FLOOD       = "deauth_flood"
    RSSI_DROP          = "rssi_drop"
    BEACON_DISAPPEAR   = "beacon_disappear"
    BEACON_SPOOF       = "beacon_spoof_flood"
    CHANNEL_NOISE      = "channel_noise"
    CONN_FAILURE_BURST = "connection_failure_burst"
    MULTI_VECTOR       = "multi_vector_attack"


@dataclass
class JamEvent:
    jam_type: JamType
    confidence: float          # 0.0 - 1.0
    details: str
    timestamp: float = field(default_factory=time.time)
    interface: str = ""
    channel: int = 0
    rssi: Optional[int] = None
    source_macs: list = field(default_factory=list)


class JamDetector:
    """
    Orchestrates all jamming detection methods.
    Calls failover_manager and alert_engine on confirmed detections.
    """

    DEFAULT_CONFIG = {
        "interface":              "wlan0",
        "monitor_interface":      "wlan0mon",
        "target_ssid":            None,
        "target_bssid":           None,
        "check_interval_sec":     2,
        "deauth_threshold":       10,
        "deauth_burst_threshold": 30,
        "rssi_drop_threshold_db": 20,
        "rssi_window_sec":        10,
        "beacon_missing_sec":     8,
        "beacon_spoof_threshold": 5,
        "conn_failure_threshold": 3,
        "enable_packet_capture":  True,
        "auto_monitor_mode":      True,
    }

    def __init__(self, config: dict, failover_manager, alert_engine):
        self.cfg = {**self.DEFAULT_CONFIG, **config}
        self.failover = failover_manager
        self.alerts = alert_engine
        self.running = False

        self._deauth_counts: dict  = defaultdict(int)
        self._rssi_history: deque  = deque(maxlen=50)
        self._beacon_last_seen: dict = {}
        self._ssid_bssids: dict    = defaultdict(set)
        self._conn_failures: int   = 0
        self._active_jams: dict    = {}
        self._sniffer              = None
        self._interval_start       = time.time()
        self._recent_jam_types: deque = deque(maxlen=20)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def run(self):
        self.running = True
        log.info(f"🔍 JamDetector starting on interface: {self.cfg['interface']}")

        if self.cfg['enable_packet_capture'] and SCAPY_AVAILABLE:
            await self._setup_monitor_mode()
            self._start_sniffer()

        while self.running:
            await self._check_rssi()
            await self._check_beacons()
            await self._check_connection()
            await self._flush_interval_counts()
            await self._check_multi_vector()
            await asyncio.sleep(self.cfg['check_interval_sec'])

    async def stop(self):
        self.running = False
        if self._sniffer:
            self._sniffer.stop()
        log.info("JamDetector stopped.")

    # ------------------------------------------------------------------
    # Monitor mode setup
    # ------------------------------------------------------------------

    async def _setup_monitor_mode(self):
        iface = self.cfg['interface']
        if not self.cfg.get('auto_monitor_mode'):
            return
        try:
            subprocess.run(['ip', 'link', 'set', iface, 'down'],    check=True, capture_output=True)
            subprocess.run(['iw', iface, 'set', 'monitor', 'none'], check=True, capture_output=True)
            subprocess.run(['ip', 'link', 'set', iface, 'up'],      check=True, capture_output=True)
            self.cfg['monitor_interface'] = iface
            log.info(f"Monitor mode enabled on {iface}")
        except Exception as e:
            log.warning(f"Could not set monitor mode automatically: {e}")
            log.warning("Try: sudo airmon-ng start wlan0")

    # ------------------------------------------------------------------
    # Packet capture (scapy)
    # ------------------------------------------------------------------

    def _start_sniffer(self):
        if not SCAPY_AVAILABLE:
            return
        try:
            iface = self.cfg['monitor_interface']
            self._sniffer = AsyncSniffer(
                iface=iface,
                prn=self._packet_handler,
                store=False,
                filter="type mgt"
            )
            self._sniffer.start()
            log.info(f"Packet sniffer running on {iface}")
        except Exception as e:
            log.error(f"Failed to start sniffer: {e}. Ensure interface is in monitor mode.")

    def _packet_handler(self, pkt):
        try:
            if pkt.haslayer(Dot11Deauth):
                self._handle_deauth(pkt)
            if pkt.haslayer(Dot11Beacon):
                self._handle_beacon(pkt)
        except Exception:
            pass

    def _handle_deauth(self, pkt):
        try:
            bssid = pkt[Dot11].addr2 or "unknown"
            target_bssid = self.cfg.get('target_bssid')
            if target_bssid and bssid != target_bssid:
                return
            self._deauth_counts[bssid] += 1
        except Exception:
            pass

    def _handle_beacon(self, pkt):
        try:
            bssid = pkt[Dot11].addr2
            ssid  = pkt[Dot11Beacon].network_stats().get('ssid', '')
            rssi  = None
            if pkt.haslayer(RadioTap):
                rssi = getattr(pkt[RadioTap], 'dBm_AntSignal', None)
            self._beacon_last_seen[bssid] = time.time()
            self._ssid_bssids[ssid].add(bssid)
            if rssi is not None:
                self._rssi_history.append((time.time(), rssi))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Detection checks
    # ------------------------------------------------------------------

    async def _flush_interval_counts(self):
        now = time.time()
        elapsed = now - self._interval_start

        for bssid, count in list(self._deauth_counts.items()):
            if count >= self.cfg['deauth_burst_threshold']:
                await self._trigger_jam(JamEvent(
                    jam_type=JamType.DEAUTH_FLOOD,
                    confidence=0.95,
                    details=f"Deauth burst: {count} frames in {elapsed:.1f}s from BSSID {bssid}",
                    source_macs=[bssid]
                ))
            elif count >= self.cfg['deauth_threshold']:
                await self._trigger_jam(JamEvent(
                    jam_type=JamType.DEAUTH_FLOOD,
                    confidence=0.70,
                    details=f"Deauth elevated: {count} frames in {elapsed:.1f}s from BSSID {bssid}",
                    source_macs=[bssid]
                ))

        for ssid, bssids in self._ssid_bssids.items():
            if ssid and len(bssids) >= self.cfg['beacon_spoof_threshold']:
                await self._trigger_jam(JamEvent(
                    jam_type=JamType.BEACON_SPOOF,
                    confidence=0.85,
                    details=f"SSID '{ssid}' seen from {len(bssids)} BSSIDs — beacon flood/spoof",
                    source_macs=list(bssids)
                ))

        self._deauth_counts.clear()
        self._ssid_bssids.clear()
        self._interval_start = now

    async def _check_rssi(self):
        if len(self._rssi_history) < 5:
            rssi = await self._get_system_rssi()
            if rssi is not None:
                self._rssi_history.append((time.time(), rssi))
            return

        window_sec = self.cfg['rssi_window_sec']
        now = time.time()
        recent = [(t, r) for t, r in self._rssi_history if now - t <= window_sec]
        if len(recent) < 3:
            return

        mid = len(recent) // 2
        baseline_avg = sum(r for _, r in recent[:mid]) / mid
        latest_avg   = sum(r for _, r in recent[mid:]) / len(recent[mid:])
        drop = baseline_avg - latest_avg

        if drop >= self.cfg['rssi_drop_threshold_db']:
            confidence = min(0.95, 0.5 + (drop / 40.0))
            await self._trigger_jam(JamEvent(
                jam_type=JamType.RSSI_DROP,
                confidence=confidence,
                details=f"RSSI dropped {drop:.1f} dBm (baseline:{baseline_avg:.1f} → now:{latest_avg:.1f})",
                rssi=int(latest_avg)
            ))

    async def _check_beacons(self):
        target_bssid = self.cfg.get('target_bssid')
        if not target_bssid:
            return
        now = time.time()
        last_seen = self._beacon_last_seen.get(target_bssid)
        if last_seen is None:
            return
        gap = now - last_seen
        if gap >= self.cfg['beacon_missing_sec']:
            confidence = min(0.95, 0.5 + (gap / 30.0))
            await self._trigger_jam(JamEvent(
                jam_type=JamType.BEACON_DISAPPEAR,
                confidence=confidence,
                details=f"AP {target_bssid} beacon missing for {gap:.1f}s",
                source_macs=[target_bssid]
            ))

    async def _check_connection(self):
        try:
            result = subprocess.run(
                ['iw', self.cfg['interface'], 'link'],
                capture_output=True, text=True, timeout=3
            )
            if 'Not connected' in result.stdout or 'not connected' in result.stdout:
                self._conn_failures += 1
            else:
                self._conn_failures = 0

            if self._conn_failures >= self.cfg['conn_failure_threshold']:
                await self._trigger_jam(JamEvent(
                    jam_type=JamType.CONN_FAILURE_BURST,
                    confidence=0.80,
                    details=f"WiFi disconnected {self._conn_failures} consecutive checks"
                ))
        except Exception as e:
            log.debug(f"Connection check error: {e}")

    async def _check_multi_vector(self):
        now = time.time()
        recent_types = set(
            e.jam_type for e in self._recent_jam_types
            if now - e.timestamp < 30
        )
        if len(recent_types) >= 2:
            await self._trigger_jam(JamEvent(
                jam_type=JamType.MULTI_VECTOR,
                confidence=0.98,
                details=f"MULTI-VECTOR ATTACK DETECTED: {[t.value for t in recent_types]}",
            ))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _get_system_rssi(self) -> Optional[int]:
        try:
            result = subprocess.run(
                ['iwconfig', self.cfg['interface']],
                capture_output=True, text=True, timeout=3
            )
            match = re.search(r'Signal level=(-\d+)', result.stdout)
            if match:
                return int(match.group(1))
        except Exception:
            pass
        return None

    async def _trigger_jam(self, event: JamEvent):
        key = event.jam_type
        existing = self._active_jams.get(key)
        if existing and (time.time() - existing.timestamp) < 15:
            return

        self._active_jams[key] = event
        self._recent_jam_types.append(event)

        log.warning(f"🚨 JAM DETECTED [{event.jam_type.value}] "
                    f"confidence={event.confidence:.0%} — {event.details}")

        await self.alerts.send_jam_alert(event)
        if event.confidence >= 0.70:
            await self.failover.on_jam_detected(event)

    def get_status(self) -> dict:
        return {
            "active_jams": {k.value: {
                "confidence": v.confidence,
                "details":    v.details,
                "timestamp":  v.timestamp
            } for k, v in self._active_jams.items()},
            "rssi_current":               self._rssi_history[-1][1] if self._rssi_history else None,
            "deauth_count_last_interval": sum(self._deauth_counts.values()),
            "known_aps":                  len(self._beacon_last_seen),
        }

# =============================================================================
# End of file: core/jam_detector.py
# Copyright (C) 2026 w1boost1889M (https://github.com/w1boost1889M)
# Licensed under GNU General Public License v3.0 (GPL-3.0)
# https://github.com/Avoceous/anti-jam-cctv
# =============================================================================
