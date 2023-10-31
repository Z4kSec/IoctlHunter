import logging
import threading
import sys
from colorama import init, Fore, Style


class CustomLogger(logging.Formatter):
    """This Formatter class is used to format log in STDOUT (with colors and icon)"""

    def __init__(self, ts):
        init(convert=True)
        self._figures = {
            "debug": "o",
            "info": "*",
            "result": "+",
            "warning": "~",
            "error": "×",
        }

        self.dbg_fmt = (
            f"{Fore.MAGENTA}[{self._figures['debug']}]{Style.RESET_ALL} %(msg)s"
        )
        self.info_fmt = f"{Fore.BLUE}[{self._figures['info']}]{Style.RESET_ALL} %(msg)s"
        self.result_fmt = (
            f"{Fore.GREEN}[{self._figures['result']}]{Style.RESET_ALL} %(msg)s"
        )
        self.warn_fmt = (
            f"{Fore.YELLOW}[{self._figures['warning']}]{Style.RESET_ALL} %(msg)s"
        )
        self.err_fmt = f"{Fore.RED}[{self._figures['error']}] %(msg)s{Style.RESET_ALL}"

        if ts:
            self.dbg_fmt = f"{Fore.LIGHTBLACK_EX}%(asctime)s {self.dbg_fmt}"
            self.info_fmt = f"{Fore.LIGHTBLACK_EX}%(asctime)s {self.info_fmt}"
            self.result_fmt = f"{Fore.LIGHTBLACK_EX}%(asctime)s {self.result_fmt}"
            self.warn_fmt = f"{Fore.LIGHTBLACK_EX}%(asctime)s {self.warn_fmt}"
            self.err_fmt = f"{Fore.LIGHTBLACK_EX}%(asctime)s {self.err_fmt}"

        super().__init__(fmt="%(levelno)d: %(msg)s", datefmt=None, style="%")

    def format(self, record):
        format_orig = self._style._fmt

        if record.levelno == logging.DEBUG:
            self._style._fmt = self.dbg_fmt

        elif record.levelno == logging.INFO:
            self._style._fmt = self.info_fmt

        elif record.levelno == logging.WARN:
            self._style._fmt = self.warn_fmt

        elif record.levelno == logging.ERROR:
            self._style._fmt = self.err_fmt

        else:
            self._style._fmt = self.result_fmt

        result = logging.Formatter.format(self, record)
        self._style._fmt = format_orig

        return result


class ClosingStreamHandler(logging.StreamHandler):
    def close(self):
        self.flush()
        super().close()


def add_result_level():
    logger = logging.getLogger("ioctl-hunter")
    logging.addLevelName(25, "RESULT")
    setattr(
        logger,
        "result",
        lambda message, *args: logging.getLogger("ioctl-hunter")._log(
            25, message, args
        ),
    )


def load_custom_logger(ts=False):
    threading.current_thread().name = ""
    cust_logger = CustomLogger(ts)
    s_hdlr = ClosingStreamHandler(sys.stdout)
    s_hdlr.setFormatter(cust_logger)
    logger = logging.getLogger("ioctl-hunter")
    logger.handlers = []
    logger.addHandler(s_hdlr)
    logger.setLevel(logging.INFO)
    add_result_level()
