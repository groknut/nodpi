

from abc import ABC, abstractmethod
from config import ProxyConfig
from typing import List
import os
from urllib.request import urlopen, Request
from urllib.error import URLError
from logger import ILogger
import sys
import ssl


class IBlacklistManager(ABC):
    """Interface for blacklist management"""

    @abstractmethod
    def is_blocked(self, domain: str) -> bool:
        """Check if domain is in blacklist"""

    @abstractmethod
    async def check_domain(self, domain: bytes) -> None:
        """Automatically check if domain is blocked"""

class FileBlacklistManager(IBlacklistManager):
    """Blacklist manager that uses file-based blacklist"""

    def __init__(self, config: ProxyConfig):

        self.config = config
        self.blacklist_file = self.config.blacklist_file
        self.blocked: List[str] = []
        self.load_blacklist()

    def load_blacklist(self) -> None:
        """Load blacklist from file"""

        if not os.path.exists(self.blacklist_file):
            raise FileNotFoundError(f"File {self.blacklist_file} not found")

        with open(self.blacklist_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if len(line.strip()) < 2 or line.strip()[0] == '#':
                    continue
                self.blocked.append(line.strip().lower().replace('www.', ''))

    def is_blocked(self, domain: str) -> bool:
        """Check if domain is in blacklist"""

        domain = domain.replace('www.', '')

        if self.config.domain_matching == "loose":
            for blocked_domain in self.blocked:
                if blocked_domain in domain:
                    return True

        if domain in self.blocked:
            return True

        parts = domain.split('.')
        for i in range(1, len(parts)):
            parent_domain = '.'.join(parts[i:])
            if parent_domain in self.blocked:
                return True

        return False

    async def check_domain(self, domain: bytes) -> None:
        """Not used in file-based mode"""


class AutoBlacklistManager(IBlacklistManager):
    """Blacklist manager that automatically detects blocked domains"""

    def __init__(self, config: ProxyConfig,):

        self.blacklist_file = config.blacklist_file
        self.blocked: List[str] = []
        self.whitelist: List[str] = []

    def is_blocked(self, domain: str) -> bool:
        """Check if domain is in blacklist"""

        if domain in self.blocked:
            return True

        return False

    async def check_domain(self, domain: bytes) -> None:
        """Automatically check if domain is blocked"""

        if domain.decode() in self.blocked or domain in self.whitelist:
            return

        try:
            req = Request(
                f"https://{domain.decode()}", headers={"User-Agent": "Mozilla/5.0"}
            )
            context = ssl._create_unverified_context()

            with urlopen(req, timeout=4, context=context):
                self.whitelist.append(domain.decode())
        except URLError as e:
            reason = str(e.reason)
            if "handshake operation timed out" in reason:
                self.blocked.append(domain.decode())
                with open(self.blacklist_file, "a", encoding="utf-8") as f:
                    f.write(domain.decode() + "\n")


class NoBlacklistManager(IBlacklistManager):
    """Blacklist manager that doesn't block anything"""

    def is_blocked(self, domain: str) -> bool:
        """Check if domain is in blacklist"""
        return True

    async def check_domain(self, domain: bytes) -> None:
        """Not used in no-blacklist mode"""

class BlacklistManagerFactory:
    """Factory for creating blacklist managers"""

    @staticmethod
    def create(config: ProxyConfig, logger: ILogger) -> IBlacklistManager:
        if config.no_blacklist:
            return NoBlacklistManager()
        if config.auto_blacklist:
            return AutoBlacklistManager(config)

        try:
            return FileBlacklistManager(config)
        except FileNotFoundError as e:
            logger.error(f"\033[91m[ERROR]: {e}\033[0m")
            sys.exit(1)
