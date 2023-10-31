from pkg_resources import resource_filename


def get_hex_from_hexdump(hexdump):
    hex = ""
    for chunck in hexdump.split("\n")[1:]:
        hex += chunck[12:][:47].replace(" ", "")
    return hex


def get_ioctl_code_details(ioctl_code):
    int_ioctl_code = int(ioctl_code)
    device = (int_ioctl_code >> 16) & 0xFFFF
    access = (int_ioctl_code >> 14) & 3
    function = (int_ioctl_code) >> 2 & 0xFFF
    method = int_ioctl_code & 3
    return hex(device), hex(access), hex(function), hex(method)


def get_frida_script_content():
    script_path = resource_filename("ioctl_hunter.frida", "script.ts")
    f = open(script_path, mode="r")
    script_content = f.read()
    f.close()
    return script_content


def format_filter_list(filter_list):
    formated_filter_list = " ".join(filter_list)
    if not formated_filter_list:
        formated_filter_list = "None"
    return formated_filter_list
