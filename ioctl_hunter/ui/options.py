import argparse
import logging
import sys
from ..utils.logger import load_custom_logger

logger = logging.getLogger("ioctl-hunter")


class Options:
    def __init__(self, cli_parser):
        self.verbose = cli_parser.verbose
        self.timestamps = cli_parser.timestamps
        self.output = cli_parser.output
        self.pid = cli_parser.pid
        self.exe_path = cli_parser.exe
        self.excluded_ioctls = cli_parser.excluded_ioctls
        self.included_ioctls = cli_parser.included_ioctls
        self.excluded_drivers = cli_parser.excluded_drivers
        self.included_drivers = cli_parser.included_drivers
        self.enable_hex_out = cli_parser.enable_hex_out
        self.hook_on_start = cli_parser.hook_on_start
        self.x32 = cli_parser.x32
        self.args = cli_parser.args
        self.all_symbols = cli_parser.all_symbols

    def process(self):
        logger.info("Loading options...")
        if not self.check_misc():
            return False
        return True

    def check_misc(self):
        if self.timestamps:
            load_custom_logger(ts=True)
        if self.verbose:
            logger.setLevel(logging.DEBUG)
        return True


def get_cli_args():
    parser = argparse.ArgumentParser(
        prog="IoctlHunter",
        epilog="/!\ IoctlHunter provides dynamic key binding, please press [h] while running to get more information /!\\",
    )

    # IoctlHunter attributes
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=False,
        help="Enable debugging messages",
    )
    parser.add_argument(
        "-ts",
        "--timestamps",
        action="store_true",
        default=False,
        help="Display timestamps for each log",
    )

    # Executable
    group_custom_agent = parser.add_argument_group("Targeted executable / process")
    group_custom_agent = group_custom_agent.add_mutually_exclusive_group(required=True)
    group_custom_agent.add_argument(
        "-e",
        "--exe",
        action="store",
        default=None,
        help="Path to an executable to run and to be orchestrated with IoctlHunter",
    )
    group_custom_agent.add_argument(
        "-p",
        "--pid",
        type=int,
        action="store",
        default=None,
        help="Pid of a running process to be orchestrated with IoctlHunter",
    )

    # Executable options
    group_agent_opts = parser.add_argument_group("Process options")
    group_agent_opts.add_argument(
        "-a",
        "--args",
        nargs="+",
        default=[],
        help='Arguments to be provided to the executable that will be spawned (ex. "-a arg1 arg2 arg3")',
    )
    group_agent_opts.add_argument(
        "-x32",
        "--x32",
        action="store_true",
        default=False,
        help="Injected process is running a 32bits binary",
    )

    # Filters attributes
    group_filters = parser.add_argument_group("Filters")
    group_filters.add_argument(
        "-eio",
        "--excluded-ioctls",
        nargs="+",
        default=[],
        help='List of IOCTLs in DECIMAL you want to exclude (ex. "-eio 2201288764 2201288765 2201288766")',
    )
    group_filters.add_argument(
        "-iio",
        "--included-ioctls",
        nargs="+",
        default=[],
        help='List of IOCTLs in DECIMAL you want to include (ex. "-iio 2201288764 2201288765 2201288766")',
    )
    group_filters.add_argument(
        "-edrv",
        "--excluded-drivers",
        nargs="+",
        default=[],
        help='List of drivers you want to exclude (ex. "-edrv livekd procexp")',
    )
    group_filters.add_argument(
        "-idrv",
        "--included-drivers",
        nargs="+",
        default=[],
        help='List of drivers you want to include (ex. "-idrv livekd procexp")',
    )

    # Hooking attributes
    group_hooking = parser.add_argument_group("Hooking modes")
    group_hooking.add_argument(
        "-eho",
        "--enable-hex-out",
        action="store_true",
        default=False,
        help="Enable the display of IoDeviceControl() the output buffer hexdump",
    )
    group_hooking.add_argument(
        "-hos",
        "--hook-on-start",
        action="store_true",
        default=False,
        help="Enable the hooking directly after injecting into the process",
    )
    group_hooking.add_argument(
        "-as",
        "--all-symbols",
        action="store_true",
        default=False,
        help="Hook all version of a similar symbols (Nt*, Zw*, *A, *W, etc.), you'll have duplicated IOCTLs",
    )

    # Results attributes
    group_results = parser.add_argument_group("Results")
    group_results.add_argument(
        "-o",
        "--output",
        help="Local path to a file where IoctlHunter results will be stored"
        " (automatically creates the file if it does not exit)",
    )

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    return parser.parse_args()
