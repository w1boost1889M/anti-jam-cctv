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
# File     : core/alert_engine.py
# =============================================================================
"""
alert_engine.py — Multi-Channel Alert System
=============================================
Supports:
  - Telegram Bot  (instant mobile push notification)
  - Email         (SMTP — Gmail, Outlook, custom)
  - Webhooks      (Slack, Discord, Teams, custom HTTP POST)
  - MQTT          (Home Assistant / industrial SCADA integration)
  - Local syslog

All channels are dispatched concurrently with rate-limiting
to prevent alert spam during sustained attacks.
"""

import asyncio
import logging
import json
import time
import smtplib
import socket
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional

log = logging.getLogger("AlertEngine")

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    log.warning("aiohttp not installed — Telegram/webhook alerts disabled. Run: pip install aiohttp")

try:
    import paho.mqtt.client as mqtt
    MQTT_AVAILABLE = True
except ImportError:
    MQTT_AVAILABLE = False


class AlertEngine:
    """
    Dispatches alerts through all configured channels.
    Rate-limits alerts to avoid notification spam during sustained attacks.
    """

    DEFAULT_CONFIG = {
        "rate_limit_sec": 30,
        "telegram": {
            "enabled":   False,
            "bot_token": "",
            "chat_id":   "",
        },
        "email": {
            "enabled":   False,
            "smtp_host": "smtp.gmail.com",
            "smtp_port": 587,
            "username":  "",
            "password":  "",
            "from":      "",
            "to":        [],
        },
        "webhook": {
            "enabled": False,
            "url":     "",
            "method":  "POST",
        },
        "mqtt": {
            "enabled":       False,
            "broker":        "localhost",
            "port":          1883,
            "topic_prefix":  "antijam/cctv",
        },
    }

    def __init__(self, config: dict):
        self.cfg = self._deep_merge(self.DEFAULT_CONFIG, config)
        self._rate_cache: dict = {}
        self._mqtt_client = None

        if self.cfg['mqtt']['enabled'] and MQTT_AVAILABLE:
            self._setup_mqtt()

    def _deep_merge(self, base: dict, override: dict) -> dict:
        result = base.copy()
        for k, v in override.items():
            if isinstance(v, dict) and isinstance(result.get(k), dict):
                result[k] = self._deep_merge(result[k], v)
            else:
                result[k] = v
        return result

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def send_jam_alert(self, jam_event):
        """Send jamming detection alert via all channels."""
        msg = (
            f"🚨 WIFI JAMMING DETECTED\n"
            f"Type: {jam_event.jam_type.value}\n"
            f"Confidence: {jam_event.confidence:.0%}\n"
            f"Details: {jam_event.details}\n"
            f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Host: {socket.gethostname()}\n"
            f"Powered by: Anti-Jam CCTV (github.com/Avoceous)"
        )
        await self._dispatch(f"jam_{jam_event.jam_type.value}", msg, priority="HIGH")

    async def send_failover_alert(self, message: str):
        """Send network failover status alert."""
        msg = (
            f"⚡ FAILOVER EVENT\n"
            f"{message}\n"
            f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Powered by: Anti-Jam CCTV (github.com/Avoceous)"
        )
        await self._dispatch("failover", msg, priority="HIGH")

    async def send_camera_alert(self, camera_name: str, status: str, details: str):
        """Send camera stream status alert."""
        icon = "📴" if status == "OFFLINE" else "✅"
        msg = (
            f"{icon} CAMERA {status}\n"
            f"Camera: {camera_name}\n"
            f"Details: {details}\n"
            f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}"
        )
        await self._dispatch(f"camera_{camera_name}", msg)

    # ------------------------------------------------------------------
    # Dispatch with rate limiting
    # ------------------------------------------------------------------

    async def _dispatch(self, alert_key: str, message: str, priority: str = "NORMAL"):
        now = time.time()
        last = self._rate_cache.get(alert_key, 0)
        rate_limit = self.cfg['rate_limit_sec']
        if priority == "HIGH":
            rate_limit = min(rate_limit, 10)
        if now - last < rate_limit:
            log.debug(f"Alert rate-limited: {alert_key}")
            return

        self._rate_cache[alert_key] = now
        log.info(f"📢 Alert dispatching: {message[:80]}...")

        tasks = []
        if self.cfg['telegram']['enabled']:
            tasks.append(self._send_telegram(message))
        if self.cfg['email']['enabled']:
            tasks.append(self._send_email(message))
        if self.cfg['webhook']['enabled']:
            tasks.append(self._send_webhook(message))
        if self.cfg['mqtt']['enabled'] and self._mqtt_client:
            self._send_mqtt(alert_key, message)

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, Exception):
                    log.error(f"Alert delivery error: {r}")

    # ------------------------------------------------------------------
    # Channel implementations
    # ------------------------------------------------------------------

    async def _send_telegram(self, message: str):
        if not AIOHTTP_AVAILABLE:
            return
        token   = self.cfg['telegram']['bot_token']
        chat_id = self.cfg['telegram']['chat_id']
        if not token or not chat_id:
            return
        url     = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {"chat_id": chat_id, "text": message, "parse_mode": "Markdown"}
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload,
                                        timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status != 200:
                        log.error(f"Telegram API error: {resp.status}")
                    else:
                        log.debug("Telegram alert sent ✓")
        except Exception as e:
            log.error(f"Telegram send error: {e}")

    async def _send_email(self, message: str):
        cfg = self.cfg['email']
        if not cfg['username'] or not cfg['to']:
            return
        try:
            msg = MIMEMultipart()
            msg['From']    = cfg['from'] or cfg['username']
            msg['To']      = ', '.join(cfg['to'])
            msg['Subject'] = "🚨 Anti-Jam CCTV Alert — github.com/Avoceous"
            msg.attach(MIMEText(message, 'plain'))
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._smtp_send, msg, cfg)
            log.debug("Email alert sent ✓")
        except Exception as e:
            log.error(f"Email send error: {e}")

    def _smtp_send(self, msg, cfg):
        with smtplib.SMTP(cfg['smtp_host'], cfg['smtp_port']) as server:
            server.starttls()
            server.login(cfg['username'], cfg['password'])
            server.sendmail(cfg['from'] or cfg['username'],
                            cfg['to'], msg.as_string())

    async def _send_webhook(self, message: str):
        if not AIOHTTP_AVAILABLE:
            return
        url = self.cfg['webhook']['url']
        if not url:
            return
        payload = {"text": message, "content": message}
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload,
                                        timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status not in (200, 204):
                        log.error(f"Webhook error: {resp.status}")
                    else:
                        log.debug("Webhook alert sent ✓")
        except Exception as e:
            log.error(f"Webhook send error: {e}")

    def _setup_mqtt(self):
        try:
            cfg = self.cfg['mqtt']
            self._mqtt_client = mqtt.Client()
            self._mqtt_client.connect(cfg['broker'], cfg['port'], 60)
            self._mqtt_client.loop_start()
            log.info(f"MQTT connected to {cfg['broker']}:{cfg['port']}")
        except Exception as e:
            log.error(f"MQTT setup error: {e}")

    def _send_mqtt(self, topic_suffix: str, message: str):
        try:
            topic = f"{self.cfg['mqtt']['topic_prefix']}/{topic_suffix}"
            self._mqtt_client.publish(topic, json.dumps({
                "message":   message,
                "timestamp": time.time(),
                "source":    "github.com/Avoceous/anti-jam-cctv"
            }))
        except Exception as e:
            log.error(f"MQTT publish error: {e}")

# =============================================================================
# End of file: core/alert_engine.py
# Copyright (C) 2026 w1boost1889M (https://github.com/w1boost1889M)
# Licensed under GNU General Public License v3.0 (GPL-3.0)
# https://github.com/Avoceous/anti-jam-cctv
# =============================================================================
