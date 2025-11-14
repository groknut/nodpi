#!/usr/bin/env python3

"""
NoDPI
=====

NoDPI is a utility for bypassing the DPI (Deep Packet Inspection) system
"""
import argparse
import asyncio
import logging
import os
import sys

from proxy_server import ProxyServer
from config import ConfigLoader
from logger import ProxyLogger
from blacklist_manager import BlacklistManagerFactory
from statistic import Statistics

if sys.platform == "win32":
    pass

os.system("")

class ProxyApplication:
    """Main application class"""

    @staticmethod
    def parse_args():
        """Parse command line arguments"""

        parser = argparse.ArgumentParser()
        parser.add_argument(
            "-c", "--config", default="config.json", help="Path to config file (default: config.json)"
        )
         
        return parser.parse_args()

    @classmethod
    async def run(cls):
        """Run the proxy application"""

        logging.getLogger("asyncio").setLevel(logging.CRITICAL)

        args = cls.parse_args()

        config = ConfigLoader.load_from_json(args.config)

        logger = ProxyLogger(
            config.log_access_file, config.log_error_file, config.quiet
        )
        blacklist_manager = BlacklistManagerFactory.create(config, logger)
        statistics = Statistics()

        logger.set_error_counter_callback(
            statistics.increment_error_connections)

        proxy = ProxyServer(config, blacklist_manager, statistics, logger)

        try:
            await proxy.run()
        except asyncio.CancelledError:
            await proxy.shutdown()
            logger.info(
                "\n"*6 + "\033[92m[INFO]:\033[97m Shutting down proxy...")
            try:
                if sys.platform == "win32":
                    os.system("mode con: lines=3000")
                sys.exit(0)
            except asyncio.CancelledError:
                pass


if __name__ == "__main__":
    try:
        asyncio.run(ProxyApplication.run())
    except KeyboardInterrupt:
        pass
