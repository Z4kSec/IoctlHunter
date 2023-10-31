import logging
from ..core import IoctlHunter
from .options import Options, get_cli_args
from .keys_reader import KeysListenner

logger = logging.getLogger("ioctl-hunter")


class Console:
    def __init__(self):
        self.__opts = None

    def __run(self):
        self.ioctl_hunter = IoctlHunter(
            pid=self.__opts.pid,
            exe_path=self.__opts.exe_path,
            args=self.__opts.args,
            excluded_drivers=self.__opts.excluded_drivers,
            included_drivers=self.__opts.included_drivers,
            excluded_ioctls=self.__opts.excluded_ioctls,
            included_ioctls=self.__opts.included_ioctls,
            enable_hex_out=self.__opts.enable_hex_out,
            hook_on_start=self.__opts.hook_on_start,
            x32=self.__opts.x32,
            all_symbols=self.__opts.all_symbols,
            quiet=False,
        )
        KeysListenner()
        self.ioctl_hunter.run()

    def start(self):
        cli_parser = get_cli_args()
        self.__opts = Options(cli_parser)
        if not self.__opts.process():
            logger.error("The provided options are invalids")
            return False
        self.__run()
        return True

    def stop(self):
        if self.__opts.output:
            self.ioctl_hunter.save_output(self.__opts.output)
            return True
        return False
