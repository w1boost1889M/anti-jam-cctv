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
# File     : main.py
# =============================================================================
"""
Anti-Jam CCTV Protection System — Entry Point
==============================================
Real-time multi-vector WiFi jamming detection and automatic failover
for CCTV/IP camera systems. Detects deauth floods, RF jamming, beacon
spoofing, and RSSI drops — then auto-switches to 4G/LTE or local SD.

Usage:
    sudo python3 main.py --config config.yaml
    sudo python3 main.py --interface wlan0 --cameras rtsp://192.168.1.100/stream1
"""

import asyncio
import argparse
import logging
import signal
import sys
import yaml
from pathlib import Path

from core.jam_detector import JamDetector
from core.failover_manager import FailoverManager
from core.stream_monitor import StreamMonitor
from core.alert_engine import AlertEngine
from dashboard.web_ui import DashboardServer

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('antijam.log')
    ]
)
log = logging.getLogger("AntiJamCCTV")


def load_config(path: str) -> dict:
    with open(path, 'r') as f:
        return yaml.safe_load(f)


async def main(config: dict):
    log.info("🛡️  Anti-Jam CCTV System starting...")

    alert_engine   = AlertEngine(config.get('alerts', {}))
    failover_mgr   = FailoverManager(config.get('failover', {}), alert_engine)
    jam_detector   = JamDetector(config.get('detection', {}), failover_mgr, alert_engine)
    stream_monitor = StreamMonitor(config.get('cameras', []), failover_mgr, alert_engine)
    dashboard      = DashboardServer(config.get('dashboard', {}), jam_detector, stream_monitor, failover_mgr)

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(shutdown(
            jam_detector, stream_monitor, dashboard)))

    await asyncio.gather(
        jam_detector.run(),
        stream_monitor.run(),
        dashboard.run(),
        return_exceptions=True
    )


async def shutdown(*components):
    log.info("Shutting down Anti-Jam CCTV System...")
    for c in components:
        if hasattr(c, 'stop'):
            await c.stop()
    asyncio.get_event_loop().stop()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Anti-Jam CCTV Protection System')
    parser.add_argument('--config', default='config.yaml', help='Path to config file')
    parser.add_argument('--interface', help='WiFi monitor interface (e.g. wlan0)')
    parser.add_argument('--cameras', nargs='+', help='RTSP camera URLs')
    args = parser.parse_args()

    config_path = Path(args.config)
    if config_path.exists():
        config = load_config(str(config_path))
    else:
        log.warning(f"Config not found at {args.config}, using defaults")
        config = {}

    if args.interface:
        config.setdefault('detection', {})['interface'] = args.interface
    if args.cameras:
        config['cameras'] = [{'url': u, 'name': f'Camera_{i}'} for i, u in enumerate(args.cameras)]

    try:
        asyncio.run(main(config))
    except KeyboardInterrupt:
        log.info("Stopped by user.")

# =============================================================================
# End of file: main.py
# Copyright (C) 2026 w1boost1889M (https://github.com/w1boost1889M)
# Licensed under GNU General Public License v3.0 (GPL-3.0)
# https://github.com/w1boost1889M/anti-jam-cctv
# =============================================================================
