
from abc import ABC, abstractmethod
import logging
from typing import Optional

class ILogger(ABC):
    """Interface for logging"""

    @abstractmethod
    def log_access(self, message: str) -> None:
        """Log access message"""

    @abstractmethod
    def log_error(self, message: str) -> None:
        """Log error message"""

    @abstractmethod
    def info(self, message: str) -> None:
        """Print info message if not quiet"""

    @abstractmethod
    def error(self, message: str) -> None:
        """Print error message if not quiet"""

class ProxyLogger(ILogger):
    """Logger implementation for proxy server"""

    def __init__(
        self,
        log_access_file: Optional[str],
        log_error_file: Optional[str],
        quiet: bool = False,
    ):

        self.quiet = quiet
        self.logger = logging.getLogger(__name__)
        self.error_counter_callback = None
        self.setup_logging(log_access_file, log_error_file)

    def setup_logging(
        self, log_access_file: Optional[str], log_error_file: Optional[str]
    ) -> None:
        """Setup logging configuration"""

        class ErrorCounterHandler(logging.FileHandler):
            def __init__(self, counter_callback, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.counter_callback = counter_callback

            def emit(self, record):
                if record.levelno >= logging.ERROR:
                    self.counter_callback()
                super().emit(record)

        if log_error_file:
            error_handler = ErrorCounterHandler(
                self.increment_errors, log_error_file, encoding="utf-8"
            )
            error_handler.setFormatter(
                logging.Formatter(
                    "[%(asctime)s][%(levelname)s]: %(message)s", "%Y-%m-%d %H:%M:%S"
                )
            )
            error_handler.setLevel(logging.ERROR)
            error_handler.addFilter(
                lambda record: record.levelno == logging.ERROR)
        else:
            error_handler = logging.NullHandler()

        if log_access_file:
            access_handler = logging.FileHandler(
                log_access_file, encoding="utf-8")
            access_handler.setFormatter(logging.Formatter("%(message)s"))
            access_handler.setLevel(logging.INFO)
            access_handler.addFilter(
                lambda record: record.levelno == logging.INFO)
        else:
            access_handler = logging.NullHandler()

        self.logger.propagate = False
        self.logger.handlers = []
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(error_handler)
        self.logger.addHandler(access_handler)

    def set_error_counter_callback(self, callback):
        """Set callback for error counting"""
        self.error_counter_callback = callback

    def increment_errors(self) -> None:
        """Increment error counter"""

        if self.error_counter_callback:
            self.error_counter_callback()

    def log_access(self, message: str) -> None:
        """Log access message"""
        self.logger.info(message)

    def log_error(self, message: str) -> None:
        """Log error message"""
        self.logger.error(message)

    def info(self, *args, **kwargs) -> None:
        """Print info message if not quiet"""

        if not self.quiet:
            print(*args, **kwargs)

    def error(self, *args, **kwargs) -> None:
        """Print error message if not quiet"""

        if not self.quiet:
            print(*args, **kwargs)
