import json
import base64
import logging

logger = logging.getLogger("ioctl-hunter")


class Results:
    ioctls = {}
    count_ioctls = {}
    included_ioctls = []
    excluded_ioctls = []

    loaded_drivers = {}
    count_loaded_drivers = {}
    included_drivers = []
    excluded_drivers = []

    def __init__(self):
        pass

    def add_ioctl(self, ioctl_dict):
        ioctl_dict["buff_in"]["hexdump"] = base64.b64encode(
            bytes(ioctl_dict["buff_in"]["hexdump"], "utf-8")
        ).decode("utf-8")
        ioctl_dict["buff_out"]["hexdump"] = base64.b64encode(
            bytes(ioctl_dict["buff_out"]["hexdump"], "utf-8")
        ).decode("utf-8")
        if not ioctl_dict["ioctl"]["dec"] in self.ioctls:
            self.ioctls[ioctl_dict["ioctl"]["dec"]] = []
            self.count_ioctls[ioctl_dict["ioctl"]["dec"]] = 1
        else:
            self.count_ioctls[ioctl_dict["ioctl"]["dec"]] += 1
        self.ioctls[ioctl_dict["ioctl"]["dec"]].append(ioctl_dict)

    def add_loaded_driver(self, driver_dict):
        if not driver_dict["name"] in self.loaded_drivers:
            self.loaded_drivers[driver_dict["name"]] = driver_dict
            self.count_loaded_drivers[driver_dict["name"]] = 1
        else:
            self.count_loaded_drivers[driver_dict["name"]] += 1

    def export(self, json_fp):
        json_content = {
            "counters": {
                "ioctls": self.count_ioctls,
                "drivers": self.count_loaded_drivers,
            },
            "exclusions": {
                "ioctls": self.excluded_ioctls,
                "drivers": self.included_ioctls,
            },
            "inclusions": {
                "ioctls": self.excluded_drivers,
                "drivers": self.included_drivers,
            },
            "drivers": self.loaded_drivers,
            "ioctls": self.ioctls,
        }
        with open(json_fp, "w") as fp:
            json.dump(json_content, fp, indent=4)
