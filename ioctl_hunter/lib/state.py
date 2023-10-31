from .results import Results


class State:
    results = Results()

    script = None
    cur_proc = None

    quiet = False
    running = True
    hook_enabled = False
    debug_enabled = False
    hex_out_enabled = False

    included_drivers = []
    only_driver_handles = True
