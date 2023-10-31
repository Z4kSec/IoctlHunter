import logging
from .utils.logger import add_result_level
from .lib.hooking import start_hooking
from .lib.state import State

logger = logging.getLogger("ioctl-hunter")


class IoctlHunter:
    def __init__(
        self,
        pid=None,
        exe_path=None,
        args=None,
        included_ioctls=[],
        excluded_ioctls=[],
        excluded_drivers=[],
        included_drivers=[],
        enable_hex_out=False,
        hook_on_start=False,
        x32=False,
        all_symbols=False,
        quiet=True,
    ):
        self.__quiet = quiet
        self.__excluded_ioctls = excluded_ioctls
        self.__included_ioctls = included_ioctls
        self.__pid = pid
        self.__exe_path = exe_path
        self.__args = args
        self.__excluded_drivers = excluded_drivers
        self.__included_drivers = included_drivers
        self.__enable_hex_out = enable_hex_out
        self.__hook_on_start = hook_on_start
        self.__x32 = x32
        self.__all_symbols = all_symbols

    def run(self):
        add_result_level()
        if self.__quiet:
            logger.disabled = True
        State.results.excluded_ioctls = self.__excluded_ioctls
        State.results.included_ioctls = self.__included_ioctls
        State.results.included_drivers = self.__included_drivers
        State.results.excluded_drivers = self.__excluded_drivers
        State.hook_enabled = self.__hook_on_start
        State.hex_out_enabled = self.__enable_hex_out
        start_hooking(
            pid=self.__pid,
            exe_path=self.__exe_path,
            args=self.__args,
            x32=self.__x32,
            all_symbols=self.__all_symbols,
        )

    def save_output(self, output_path):
        try:
            State.results.export(output_path)
        except Exception as e:
            logger.error(
                f"Fail to export results to '{output_path}', due to the following error:\n    > '{str(e)}'"
            )
            return False
        return True
