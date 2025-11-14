
from datetime import datetime
from config import ProxyConfig, VERSION
from blacklist_manager import IBlacklistManager, NoBlacklistManager, AutoBlacklistManager
from statistic import IStatistics
from logger import ILogger
from connection import ConnectionHandler
import sys
import os
import textwrap
import time
import asyncio

DISCLAIMER = "DISCLAIMER. The developer and/or supplier of this software shall not be liable for any loss or damage, including but not limited to direct, indirect, incidental, punitive or consequential damages arising out of the use of or inability to use this software, even if the developer or supplier has been advised of the possibility of such damages. The developer and/or supplier of this software shall not be liable for any legal consequences arising out of the use of this software. This includes, but is not limited to, violation of laws, rules or regulations, as well as any claims or suits arising out of the use of this software. The user is solely responsible for compliance with all applicable laws and regulations when using this software."

class ProxyServer:
    """Main proxy server class"""

    def __init__(
        self,
        config: ProxyConfig,
        blacklist_manager: IBlacklistManager,
        statistics: IStatistics,
        logger: ILogger,
    ):

        self.config = config
        self.blacklist_manager = blacklist_manager
        self.statistics = statistics
        self.logger = logger
        self.connection_handler = ConnectionHandler(
            config, blacklist_manager, statistics, logger
        )
        self.server = None

        logger.set_error_counter_callback(
            statistics.increment_error_connections)

    def print_banner(self) -> None:
        """Print startup banner"""

        self.logger.info("\033]0;NoDPI\007")

        if sys.platform == "win32":
            os.system("mode con: lines=35")

        console_width = os.get_terminal_size().columns
        wrapped_text = textwrap.TextWrapper(width=70).wrap(DISCLAIMER)

        left_padding = (console_width - 76) // 2

        self.logger.info("\n\n\n")
        self.logger.info(
            "\033[91m" + " " * left_padding + "╔" + "═" * 72 + "╗" + "\033[0m"
        )

        for line in wrapped_text:
            padded_line = line.ljust(70)
            self.logger.info(
                "\033[91m" + " " * left_padding +
                "║ " + padded_line + " ║" + "\033[0m"
            )

        self.logger.info(
            "\033[91m" + " " * left_padding + "╚" + "═" * 72 + "╝" + "\033[0m"
        )
        time.sleep(1)
        self.logger.info('\033[2J\033[H')

        self.logger.info(
            """
\033[92m ██████   █████          ██████████   ███████████  █████
░░██████ ░░███          ░░███░░░░███ ░░███░░░░░███░░███
 ░███░███ ░███   ██████  ░███   ░░███ ░███    ░███ ░███
 ░███░░███░███  ███░░███ ░███    ░███ ░██████████  ░███
 ░███ ░░██████ ░███ ░███ ░███    ░███ ░███░░░░░░   ░███
 ░███  ░░█████ ░███ ░███ ░███    ███  ░███         ░███
 █████  ░░█████░░██████  ██████████   █████        █████
░░░░░    ░░░░░  ░░░░░░  ░░░░░░░░░░   ░░░░░        ░░░░░\033[0m
        """
        )
        self.logger.info(f"\033[92mVersion: {VERSION}".center(50))
        self.logger.info(
            "\033[97m" +
            "Enjoy watching! / Наслаждайтесь просмотром!".center(50)
        )

        self.logger.info("\n")
        self.logger.info(
            f"\033[92m[INFO]:\033[97m Proxy is running on {self.config.host}:{self.config.port} at {datetime.now().strftime('%H:%M on %Y-%m-%d')}"
        )
        self.logger.info(
            f"\033[92m[INFO]:\033[97m The selected fragmentation method: {self.config.fragment_method}"
        )

        self.logger.info("")
        if isinstance(self.blacklist_manager, NoBlacklistManager):
            self.logger.info(
                "\033[92m[INFO]:\033[97m Blacklist is disabled. All domains will be subject to unblocking."
            )
        elif isinstance(self.blacklist_manager, AutoBlacklistManager):
            self.logger.info(
                "\033[92m[INFO]:\033[97m Auto-blacklist is enabled")
        else:
            self.logger.info(
                f"\033[92m[INFO]:\033[97m Blacklist contains {len(self.blacklist_manager.blocked)} domains"
            )
            self.logger.info(
                f"\033[92m[INFO]:\033[97m Path to blacklist: '{self.config.blacklist_file}'"
            )

        self.logger.info("")
        if self.config.log_error_file:
            self.logger.info(
                f"\033[92m[INFO]:\033[97m Error logging is enabled. Path to error log: '{self.config.log_error_file}'"
            )
        else:
            self.logger.info(
                "\033[92m[INFO]:\033[97m Error logging is disabled")

        if self.config.log_access_file:
            self.logger.info(
                f"\033[92m[INFO]:\033[97m Access logging is enabled. Path to access log: '{self.config.log_access_file}'"
            )
        else:
            self.logger.info(
                "\033[92m[INFO]:\033[97m Access logging is disabled")

        self.logger.info("")
        self.logger.info(
            "\033[92m[INFO]:\033[97m To stop the proxy, press Ctrl+C twice"
        )
        self.logger.info("")

    async def display_stats(self) -> None:
        """Display live statistics"""

        while True:
            await asyncio.sleep(1)
            self.statistics.update_speeds()
            if not self.config.quiet:
                stats_display = self.statistics.get_stats_display()
                print(stats_display)
                print("\033[5A", end="")

    async def run(self) -> None:
        """Run the proxy server"""

        if not self.config.quiet:
            self.print_banner()

        try:
            self.server = await asyncio.start_server(
                self.connection_handler.handle_connection,
                self.config.host,
                self.config.port,
            )
        except OSError:
            self.logger.error(
                f"\033[91m[ERROR]: Failed to start proxy on this address ({self.config.host}:{self.config.port}). It looks like the port is already in use\033[0m"
            )
            sys.exit(1)

        if not self.config.quiet:
            asyncio.create_task(self.display_stats())
        asyncio.create_task(self.connection_handler.cleanup_tasks())

        await self.server.serve_forever()

    async def shutdown(self) -> None:
        """Shutdown the proxy server"""
        if self.server:
            self.server.close()
            await self.server.wait_closed()

        for task in self.connection_handler.tasks:
            task.cancel()
