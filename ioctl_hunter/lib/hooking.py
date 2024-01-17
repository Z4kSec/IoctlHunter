import ast
import time
import frida
import psutil
import logging
import datetime
from urllib.parse import unquote
from .state import State
from ..utils.misc import (
    get_ioctl_code_details,
    get_hex_from_hexdump,
    get_frida_script_content,
)
from ..ui.display import print_ioctl, print_loaded_driver, print_final_recap

logger = logging.getLogger("ioctl-hunter")


def check_drivers_filters(ioctl_dict):
    if State.results.included_drivers:
        for driver in State.results.included_drivers:
            if (
                ioctl_dict["handle_path"] != "N/A"
                and driver.lower() in ioctl_dict["handle_path"].lower()
            ):
                return True
        return False

    elif State.results.excluded_drivers:
        for driver in State.results.excluded_drivers:
            if (
                ioctl_dict["handle_path"] != "N/A"
                and driver.lower() in ioctl_dict["handle_path"].lower()
            ):
                return False

    return True


def check_ioctls_filters(ioctl_dict):
    if State.results.included_ioctls:
        return ioctl_dict["ioctl"] in State.results.included_ioctls
    elif State.results.excluded_ioctls:
        return ioctl_dict["ioctl"] not in State.results.excluded_ioctls
    else:
        return True


def process_device_ioctl_queue():
    ioctls_queue = State.script.exports.getQueueDeviceIoctl()
    open_handles = State.script.exports.getOpenHandles()

    for ioctl_elem in ioctls_queue:
        ioctl_dict = ioctl_elem
        try:
            ioctl_dict = ast.literal_eval(ioctl_elem)
        except:
            try:
                ioctl_dict = ast.literal_eval(
                    ioctl_elem.replace("\\", "\\\\").replace("\n", "\\n")
                )
            except Exception as e:
                logger.error(str(e))
                logger.error(ioctl_elem)
                continue

        ioctl_dict["timestamp"] = str(datetime.datetime.now())
        ioctl_dict["handle_device"] = {
            "dec": ioctl_dict["handle_device"],
            "hex": "{0:#010x}".format(int(ioctl_dict["handle_device"])),
        }

        if ioctl_dict["handle_path"]:
            pass
        elif open_handles.get(ioctl_dict["handle_device"]["dec"], None):
            ioctl_dict["handle_path"] = open_handles.get(
                ioctl_dict["handle_device"]["dec"]
            )
        else:
            logger.error(open_handles)
            ioctl_dict["handle_path"] = "N/A"

        if not check_drivers_filters(ioctl_dict):
            continue

        if not check_ioctls_filters(ioctl_dict):
            continue

        device, access, function, method = get_ioctl_code_details(ioctl_dict["ioctl"])
        ioctl_dict["ioctl"] = {
            "dec": ioctl_dict["ioctl"],
            "hex": "{0:#010x}".format(int(ioctl_dict["ioctl"])),
            "details": {
                "device": device,
                "access": access,
                "function": function,
                "method": method,
            },
        }

        ioctl_dict["buff_in"]["hexdump"] = unquote(ioctl_dict["buff_in"]["hexdump"])
        ioctl_dict["buff_in"]["hex"] = get_hex_from_hexdump(
            ioctl_dict["buff_in"]["hexdump"]
        )

        ioctl_dict["buff_out"]["hexdump"] = unquote(ioctl_dict["buff_out"]["hexdump"])
        ioctl_dict["buff_out"]["hex"] = get_hex_from_hexdump(
            ioctl_dict["buff_out"]["hexdump"]
        )

        print_ioctl(ioctl_dict)
        State.results.add_ioctl(ioctl_dict)
    return True


def process_loaded_drivers_queue():
    loaded_drivers_queue = State.script.exports.getQueueLoadedDrivers()
    if loaded_drivers_queue:
        for loaded_driver in loaded_drivers_queue:
            loaded_driver["timestamp"] = str(datetime.datetime.now())
            State.results.add_loaded_driver(loaded_driver)
            print_loaded_driver(loaded_driver)
    return True


def start_hooking(exe_path=None, pid=None, args=None, x32=False, all_symbols=False):
    try:
        if exe_path:
            if args:
                pid = frida.spawn(exe_path, argv=args)
            else:
                pid = frida.spawn(exe_path)
            session = frida.attach(pid)
            frida.resume(pid)
        elif pid:
            session = frida.attach(pid)
        else:
            return False

        script_content = get_frida_script_content()
        State.script = session.create_script(script_content)
        State.cur_proc = psutil.Process(pid)
        State.script.load()
    except Exception as e:
        logger.error(
            f"Fail to inject into the provided process or executable, due to the following error:\n    > '{str(e)}'"
        )
        return False

    State.script.exports.is32bits(x32)
    State.script.exports.isallsymbols(all_symbols)

    if State.hook_enabled:
        State.script.exports.setHookEnabled(State.hook_enabled)

    for ioctl in State.results.excluded_ioctls:
        State.script.exports.excludeioctl(ioctl)

    logger.info("Start hunting juicy IOCTLs")
    while State.running and psutil.pid_exists(pid):
        time.sleep(0.1)
        try:
            process_device_ioctl_queue()
            process_loaded_drivers_queue()
        except frida.InvalidOperationError:
            break

    try:
        session.detach()
        print_final_recap()
    except:
        pass
    return True