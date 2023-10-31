import sys
import logging
from ..lib.state import State
from ..utils.misc import format_filter_list

logger = logging.getLogger("ioctl-hunter")


def print_loaded_driver(loaded_driver):
    if State.debug_enabled:
        return False
    logger.warning("")
    logger.warning("-" * 30)
    logger.warning("")
    logger.warning(f"New dynamically loaded driver:")
    logger.warning(f"\t- SvcName:\t{loaded_driver['name']}")
    logger.warning(f"\t- RegKey:\t{loaded_driver['key']}")
    logger.warning(f"\t- ImagePath:\t{loaded_driver['image_path']}")
    logger.warning("")
    logger.warning("-" * 30)
    logger.warning("")
    return True


def print_ioctl(my_dict):
    if State.debug_enabled:
        return False

    logger.result("")
    logger.result("-" * 20)
    logger.result("")

    logger.result(f"Symbol:\t\t{my_dict['symbol']}")
    logger.result(f"Device path:\t{my_dict['handle_path']}")
    logger.result(
        f"Device handle:\t{my_dict['handle_device']['dec']}\t({my_dict['handle_device']['hex']})"
    )

    logger.result(
        f"Ioctl code:\t\t{my_dict['ioctl']['dec']}\t({my_dict['ioctl']['hex']})"
    )
    logger.result(f"\t- Device:\t{my_dict['ioctl']['details']['device']}")
    logger.result(f"\t- Access:\t{my_dict['ioctl']['details']['access']}")
    logger.result(f"\t- Function:\t{my_dict['ioctl']['details']['function']}")
    logger.result(f"\t- Method:\t{my_dict['ioctl']['details']['method']}")

    logger.result(f"Input buffer size:\t{my_dict['buff_in']['size']}")
    logger.result(f"Hexdump input buffer:\n{my_dict['buff_in']['hexdump']}")

    logger.result(f"Output buffer size:\t{my_dict['buff_out']['size']}")
    logger.result(f"Returned bytes:\t{my_dict['buff_out']['bytes_returned']}")
    if State.hex_out_enabled:
        logger.result(f"Hexdump output buffer:\n{my_dict['buff_out']['hexdump']}")
    logger.result("")
    logger.result("-" * 20)
    logger.result("")
    return True


def print_enable_debugger():
    State.debug_enabled = True
    logger.handlers[0].flush()
    sys.stdout.flush()

    logger.info("")
    logger.info("")
    logger.info("-" * 20 + " IoctlHunter state " + "-" * 20)
    logger.info("")

    logger.info(f"* Hook state:\t\t{State.hook_enabled}")
    logger.info("")
    logger.info(f"* Filters:")
    logger.info(
        f"\t- Included IOCTLs (decimal):\t{format_filter_list(State.results.included_ioctls)}"
    )
    logger.info(
        f"\t- Excluded IOCTLs (decimal):\t{format_filter_list(State.results.excluded_ioctls)}"
    )
    logger.info(
        f"\t- Included drivers:\t\t{format_filter_list(State.results.included_drivers)}"
    )
    logger.info(
        f"\t- Excluded drivers:\t\t{format_filter_list(State.results.excluded_drivers)}"
    )

    if len(State.results.loaded_drivers):
        logger.info("")
        logger.info(f"* Dynamically loaded drivers:")
        for driver, data in State.results.loaded_drivers.items():
            logger.info(f"\t- {driver}\t({data['image_path']})")

    if len(State.results.count_ioctls):
        logger.info("")
        logger.info(f"* IOCTLs hooked list:")
        for ioctl, count in State.results.count_ioctls.items():
            handle_path = State.results.ioctls[ioctl][0]["handle_path"]
            ioctl_hex = "{0:#010x}".format(int(ioctl))
            logger.info(f"\t- {ioctl}\t{ioctl_hex}\t{count}\t{handle_path}")

    logger.info("")
    logger.info("-" * 59)

    return True


def print_disable_debugger():
    logger.info("Leaving the debugging mode...")
    logger.info("")
    logger.info("")
    State.debug_enabled = False
    return True


def print_final_recap():
    logger.info("")
    logger.info("")
    print_enable_debugger()
    logger.info("")
    logger.info("")
    logger.info("End of the hunt !")
    logger.info("Exiting...")


def print_dynamic_helper():
    State.debug_enabled = True
    logger.handlers[0].flush()
    sys.stdout.flush()

    logger.info("")
    logger.info("")
    logger.info("-" * 20 + " IoctlHunter helper " + "-" * 20)
    logger.info("")
    logger.info("> Press [SPACE] to enable or disable the hooking engine")
    logger.info(
        "> Press [ENTER] to get all information related to the current Ioctl hunt"
    )
    logger.info("> Press [a/A] to append elements to an inclusion / exclusion list")
    logger.info("> Press [r/R] to remove elements to an inclusion / exclusion list")
    logger.info("> Press [h/H] to display this message")
    logger.info("> Press [CTRL] + [c/C] to gracefully exit IoctlHunter")
    logger.info("")
    logger.info("-" * 59)
    logger.info("")
    logger.info("")
    State.debug_enabled = False

    return True
