import sys
import threading
import time
import logging
import msvcrt
from colorama import init, Fore, Style
from ..lib.state import State
from ..ui.display import (
    print_enable_debugger,
    print_disable_debugger,
    print_dynamic_helper,
)

logger = logging.getLogger("ioctl-hunter")


class KeysListenner(threading.Thread):
    is_debugger_enabled = False

    def __init__(self):
        super(KeysListenner, self).__init__(daemon=True)
        init(convert=True)
        self.start()

    def run(self):
        while not msvcrt.kbhit():
            time.sleep(0.1)

        try:
            while True:
                result = None

                if not msvcrt.kbhit():
                    time.sleep(0.1)
                    continue

                result = msvcrt.getch().decode("utf-8")

                if result and result in ["\n", "\r"] and not self.is_debugger_enabled:
                    print_enable_debugger()
                    self.is_debugger_enabled = True
                elif result and result in ["\n", "\r"] and self.is_debugger_enabled:
                    print_disable_debugger()
                    self.is_debugger_enabled = False
                elif not self.is_debugger_enabled:
                    self.process_live_commands(result)
        except Exception as e:
            logger.warn(str(e))

    def process_live_commands(self, input_cmd):
        if not input_cmd:
            return

        if input_cmd == " ":
            self.exec_cmd_set_hook_state()
        elif input_cmd.lower() in ["a", "r"]:
            choice = self.select_list_to_update(input_cmd.lower())
            self.exec_cmd_edit_list(input_cmd.lower(), choice)
        elif input_cmd.lower() == "h":
            print_dynamic_helper()

    def exec_cmd_set_hook_state(self):
        State.hook_enabled = False if State.hook_enabled else True
        State.script.exports.setHookEnabled(State.hook_enabled)
        logger.info(f"Hook state: {State.hook_enabled}")

    def select_list_to_update(self, mode):
        if mode == "a":
            logger.info("On which list do you want to append elements?")
        else:
            logger.info("On which list do you want to remove elements?")
        logger.info("\t (1) Included IOCTLs")
        logger.info("\t (2) Excluded IOCTLs")
        logger.info("\t (3) Included drivers")
        logger.info("\t (4) Excluded drivers")
        choice = None
        try:
            while not choice:
                if not msvcrt.kbhit():
                    time.sleep(0.1)
                    continue
                choice = msvcrt.getch().decode("utf-8")
        except Exception as e:
            logger.warn(str(e))
        return choice

    def exec_cmd_edit_list(self, mode, list_choice):
        State.debug_enabled = True
        logger.handlers[0].flush()
        sys.stdout.flush()
        list_ptr = None
        msg = (
            f"{Fore.BLUE}[*]{Style.RESET_ALL} Please submit the elements to process:\n"
        )

        if list_choice == "1":
            list_ptr = State.results.included_ioctls
        elif list_choice == "2":
            list_ptr = State.results.excluded_ioctls
        elif list_choice == "3":
            list_ptr = State.results.included_drivers
        elif list_choice == "4":
            list_ptr = State.results.excluded_drivers

        if list_ptr != None:
            logger.info(f"Actual list content: {list_ptr}")
            elements = " ".join(input(msg).strip().split()).split()
            for element in elements:
                if mode == "a" and not element in list_ptr:
                    list_ptr.append(element)
                elif mode == "r" and element in list_ptr:
                    list_ptr.remove(element)
            logger.info("List successfully updated")
            logger.info("")
        State.debug_enabled = False
