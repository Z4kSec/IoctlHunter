import sys
import logging
import traceback
from .console import Console
from .display import print_final_recap
from ..utils.logger import load_custom_logger


VERSION = "0.1"
logger = logging.getLogger("ioctl-hunter")


def print_banner():
    print(
        f"""
     _____           _   _    _    _             _            
    |_   _|         | | | |  | |  | |           | |           
      | |  ___   ___| |_| |  | |__| |_   _ _ __ | |_ ___ _ __ 
      | | / _ \ / __| __| |  |  __  | | | | '_ \| __/ _ \ '__|
     _| || (_) | (__| |_| |  | |  | | |_| | | | | ||  __/ |   
    |_____\___/ \___|\__|_|  |_|  |_|\__,_|_| |_|\__\___|_| 
    v{VERSION}

    """
    )


def ctrlc_handler(exception, cli):
    logger.warn(
        "Interruption received, wait for IoctlHunter to finish running scans..."
    )
    try:
        if cli:
            cli.stop()
    except:
        pass
    print_final_recap()
    sys.exit(0)


def main():
    try:
        cli = None
        print_banner()
        load_custom_logger()
        cli = Console()
        cli.start()
        cli.stop()
    except KeyboardInterrupt as e:
        ctrlc_handler(e, cli)
    except Exception as e:
        logger.error(
            f'IoctlHunter encountered an unexpected error: "{str(e)}"\n'
            "-------------------------- Traceback --------------------------\n"
            f"{traceback.format_exc()}\n"
            "---------------------------------------------------------------\n"
            f"Please provide this output to the IoctlHunter development team\n"
        )


if __name__ == "__main__":
    main()
