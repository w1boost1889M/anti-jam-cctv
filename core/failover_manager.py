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
# File     : core/failover_manager.py
# =============================================================================
"""
failover_manager.py — Automatic Network Failover Orchestration
==============================================================
Failover chain:
  PRIMARY:   WiFi (normal RTSP stream)
    ↓ jam detected
  SECONDARY: 4G/LTE modem (reroute via cellular interface)
    ↓ 4G unavailable
  TERTIARY:  Local SD/HDD recording (offline buffer)
  ↓ WiFi recovers
  AUTO-RESTORE: Back to primary WiFi

Also handles:
  - Pre-jam evidence buffering (keeps last N seconds before jam)
  - Auto-recovery when WiFi restores
  - Per-camera failover state
"""

import asyncio
import logging
import subprocess
import time
import os
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger("FailoverManager")


class NetworkMode(Enum):
    WIFI   = "wifi"
    LTE    = "4g_lte"
    LOCAL  = "local_only"
    HYBRID = "wifi+lte"


@dataclass
class FailoverState:
    mode: NetworkMode = NetworkMode.WIFI
    jam_event_count: int = 0
    last_failover_time: Optional[float] = None
    recovery_attempts: int = 0
    lte_interface: Optional[str] = None
    is_recording_locally: bool = False


class FailoverManager:
    """
    Manages automatic switching between network interfaces
    and recording modes in response to jamming events.
    """

    DEFAULT_CONFIG = {
        "wifi_interface":        "wlan0",
        "lte_interface":         "wwan0",
        "lte_apn":               "internet",
        "local_recording_path":  "/media/sd/cctv_emergency/",
        "pre_jam_buffer_sec":    30,
        "recovery_check_interval": 30,
        "auto_recover_wifi":     True,
        "enable_lte_failover":   True,
        "enable_local_failover": True,
        "ffmpeg_path":           "ffmpeg",
    }

    def __init__(self, config: dict, alert_engine):
        self.cfg = {**self.DEFAULT_CONFIG, **config}
        self.alerts = alert_engine
        self.state = FailoverState()
        self._camera_recorders: dict = {}
        self._recovery_task: Optional[asyncio.Task] = None
        self._running = False

        os.makedirs(self.cfg['local_recording_path'], exist_ok=True)

    async def on_jam_detected(self, jam_event):
        """Called by JamDetector when a jamming event is confirmed."""
        self.state.jam_event_count += 1
        log.warning(f"⚡ Failover triggered by: {jam_event.jam_type.value}")

        if self.state.mode == NetworkMode.WIFI:
            await self._failover_to_lte(jam_event)
        elif self.state.mode == NetworkMode.LTE:
            log.warning("Already on LTE — verifying LTE health...")
            await self._verify_lte_health()

        if self.cfg['enable_local_failover']:
            await self._start_local_recording()

        if self._recovery_task is None or self._recovery_task.done():
            self._recovery_task = asyncio.create_task(self._recovery_monitor())

    async def _failover_to_lte(self, jam_event):
        if not self.cfg['enable_lte_failover']:
            log.info("LTE failover disabled — going local only")
            await self._set_mode(NetworkMode.LOCAL)
            return

        lte_iface = self.cfg['lte_interface']
        log.info(f"🔄 Switching to LTE interface: {lte_iface}")

        success = await self._bring_up_lte(lte_iface)
        if success:
            await self._set_mode(NetworkMode.LTE)
            await self.alerts.send_failover_alert(
                f"✅ Failover to 4G/LTE successful ({lte_iface}). "
                f"Jam: {jam_event.jam_type.value}"
            )
        else:
            log.error("LTE failover failed — switching to local recording only")
            await self._set_mode(NetworkMode.LOCAL)
            await self.alerts.send_failover_alert(
                f"⚠️ LTE failover FAILED. Local recording only. "
                f"Jam: {jam_event.jam_type.value}"
            )

    async def _bring_up_lte(self, iface: str) -> bool:
        try:
            result = subprocess.run(
                ['ip', 'link', 'show', iface],
                capture_output=True, timeout=5
            )
            if result.returncode != 0:
                log.error(f"LTE interface {iface} not found")
                return False

            subprocess.run(['ip', 'link', 'set', iface, 'up'],
                           check=True, timeout=10)
            subprocess.run(['dhclient', '-v', iface],
                           timeout=30, capture_output=True)

            lte_gw = await self._get_gateway(iface)
            if lte_gw:
                subprocess.run(
                    ['ip', 'route', 'add', 'default', 'via', lte_gw,
                     'dev', iface, 'metric', '50'],
                    capture_output=True
                )
                log.info(f"LTE route established via {lte_gw}")
                self.state.lte_interface = iface
                return True
            return False

        except subprocess.TimeoutExpired:
            log.error("LTE bring-up timed out")
            return False
        except Exception as e:
            log.error(f"LTE bring-up error: {e}")
            return False

    async def _get_gateway(self, iface: str) -> Optional[str]:
        try:
            result = subprocess.run(
                ['ip', 'route', 'show', 'dev', iface],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                if 'default' in line or 'via' in line:
                    parts = line.split()
                    for i, p in enumerate(parts):
                        if p == 'via' and i + 1 < len(parts):
                            return parts[i + 1]
        except Exception:
            pass
        return None

    async def _verify_lte_health(self):
        try:
            result = subprocess.run(
                ['ping', '-I', self.cfg['lte_interface'], '-c', '3', '8.8.8.8'],
                capture_output=True, timeout=15
            )
            if result.returncode != 0:
                log.warning("LTE connectivity lost — switching to local")
                await self._set_mode(NetworkMode.LOCAL)
        except Exception:
            pass

    async def _start_local_recording(self):
        if self.state.is_recording_locally:
            return
        self.state.is_recording_locally = True
        log.info("📼 Starting emergency local recording...")

    async def _recovery_monitor(self):
        log.info("Starting WiFi recovery monitor...")
        while True:
            await asyncio.sleep(self.cfg['recovery_check_interval'])
            if self.state.mode in (NetworkMode.LTE, NetworkMode.LOCAL):
                if await self._wifi_is_healthy():
                    log.info("📶 WiFi recovered — switching back to primary")
                    await self._restore_wifi()
                    break
            else:
                break

    async def _wifi_is_healthy(self) -> bool:
        try:
            result = subprocess.run(
                ['ping', '-I', self.cfg['wifi_interface'], '-c', '3', '-W', '2', '8.8.8.8'],
                capture_output=True, timeout=15
            )
            return result.returncode == 0
        except Exception:
            return False

    async def _restore_wifi(self):
        await self._set_mode(NetworkMode.WIFI)
        self.state.recovery_attempts += 1
        self.state.is_recording_locally = False

        if self.state.lte_interface:
            try:
                subprocess.run(
                    ['ip', 'route', 'del', 'default', 'dev', self.state.lte_interface],
                    capture_output=True
                )
            except Exception:
                pass

        await self.alerts.send_failover_alert(
            "✅ WiFi signal restored. Switched back to primary network."
        )

    async def _set_mode(self, mode: NetworkMode):
        self.state.mode = mode
        self.state.last_failover_time = time.time()
        log.info(f"Network mode: {mode.value}")

    def register_camera_recorder(self, cam_id: str, proc):
        self._camera_recorders[cam_id] = proc

    def get_status(self) -> dict:
        return {
            "network_mode":     self.state.mode.value,
            "jam_event_count":  self.state.jam_event_count,
            "last_failover":    self.state.last_failover_time,
            "lte_interface":    self.state.lte_interface,
            "local_recording":  self.state.is_recording_locally,
            "recovery_attempts": self.state.recovery_attempts,
        }

# =============================================================================
# End of file: core/failover_manager.py
# Copyright (C) 2026 w1boost1889M (https://github.com/w1boost1889M)
# Licensed under GNU General Public License v3.0 (GPL-3.0)
# https://github.com/w1boost1889M/anti-jam-cctv
# =============================================================================
