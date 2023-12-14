# IoctlHunter

IoctlHunter is a command-line tool designed to simplify the analysis of IOCTL calls made by userland software targeting Windows drivers.

**TL;DR: Here are the [videos demonstrating the usage of IoctlHunter](https://z4ksec.github.io/posts/ioctlhunter-release-v0.2/#demo-with-powertools)**

From a cybersecurity perspective, IoctlHunter empowers security researchers to identify IOCTL calls that could potentially be reused in standalone binaries to perform various actions, such as privilege escalation (EoP) or killing Endpoint Detection and Response (EDR) processes.

This technique, also known as BYOVD (Bring Your Own Vulnerable Driver), involves embedding a signed vulnerable driver within a binary. Once deployed on a targeted system, the binary loads the driver and sends IOCTL calls to it to execute specific offensive actions with kernel-level privileges.

A [blog post](https://z4ksec.github.io/posts/ioctlhunter-release-v0.2/) was published to detail the implemented technics and how IoctlHunter works.

### Installation

IoctlHunter can be simply installed via the public PyPi repository as following:
```
pip install ioctlhunter
```

Note that this tools is dedicated to be used on Windows environments to analyse specific process / binaries interacting with drivers. 

Moreover, [a Golang package](https://github.com/Z4kSec/IoctlHunter/tree/main/example) provided in the IoctlHunter repository allows you to load and replay the IOCTL calls. This binary can be build via the following Go commands:

```
cd .\example\
go build .
```


### Command line options

IoctlHunter is usable as a classic CLI tool. Moreover, dynamic key binding are available to ease the analysis during the execution of the targeted process / binary (press H at runtime).

Find below the actually available options:

```

     _____           _   _    _    _             _
    |_   _|         | | | |  | |  | |           | |
      | |  ___   ___| |_| |  | |__| |_   _ _ __ | |_ ___ _ __
      | | / _ \ / __| __| |  |  __  | | | | '_ \| __/ _ \ '__|
     _| || (_) | (__| |_| |  | |  | | |_| | | | | ||  __/ |
    |_____\___/ \___|\__|_|  |_|  |_|\__,_|_| |_|\__\___|_|
    v0.2


usage: IoctlHunter [-h] [-v] [-ts] (-e EXE | -p PID) [-a ARGS [ARGS ...]] [-x32] [-eio EXCLUDED_IOCTLS [EXCLUDED_IOCTLS ...]] [-iio INCLUDED_IOCTLS [INCLUDED_IOCTLS ...]]
                   [-edrv EXCLUDED_DRIVERS [EXCLUDED_DRIVERS ...]] [-idrv INCLUDED_DRIVERS [INCLUDED_DRIVERS ...]] [-eho] [-hos] [-as] [-o OUTPUT]

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         Enable debugging messages
  -ts, --timestamps     Display timestamps for each log

Targeted executable / process:
  -e EXE, --exe EXE     Path to an executable to run and to be orchestrated with IoctlHunter
  -p PID, --pid PID     Pid of a running process to be orchestrated with IoctlHunter

Process options:
  -a ARGS [ARGS ...], --args ARGS [ARGS ...]
                        Arguments to be provided to the executable that will be spawned (ex. "-a arg1 arg2 arg3")
  -x32, --x32           Injected process is running a 32bits binary

Filters:
  -eio EXCLUDED_IOCTLS [EXCLUDED_IOCTLS ...], --excluded-ioctls EXCLUDED_IOCTLS [EXCLUDED_IOCTLS ...]
                        List of IOCTLs in DECIMAL you want to exclude (ex. "-eio 2201288764 2201288765 2201288766")
  -iio INCLUDED_IOCTLS [INCLUDED_IOCTLS ...], --included-ioctls INCLUDED_IOCTLS [INCLUDED_IOCTLS ...]
                        List of IOCTLs in DECIMAL you want to include (ex. "-iio 2201288764 2201288765 2201288766")
  -edrv EXCLUDED_DRIVERS [EXCLUDED_DRIVERS ...], --excluded-drivers EXCLUDED_DRIVERS [EXCLUDED_DRIVERS ...]
                        List of drivers you want to exclude (ex. "-edrv livekd procexp")
  -idrv INCLUDED_DRIVERS [INCLUDED_DRIVERS ...], --included-drivers INCLUDED_DRIVERS [INCLUDED_DRIVERS ...]
                        List of drivers you want to include (ex. "-idrv livekd procexp")

Hooking modes:
  -eho, --enable-hex-out
                        Enable the display of IoDeviceControl() the output buffer hexdump
  -hos, --hook-on-start
                        Enable the hooking directly after injecting into the process
  -as, --all-symbols    Hook all version of a similar symbols (Nt*, Zw*, *A, *W, etc.), you'll have duplicated IOCTLs

Results:
  -o OUTPUT, --output OUTPUT
                        Local path to a file where IoctlHunter results will be stored (automatically creates the file if it does not exit)

/!\ IoctlHunter provides dynamic key binding, please press [h] while running to get more information /!\
```

Furthermore, the dynamic key bindings are the following:

```
-------------------- IoctlHunter helper --------------------

> Press [SPACE] to enable or disable the hooking engine
> Press [ENTER] to get all information related to the current Ioctl hunt
> Press [a/A] to append elements to an inclusion / exclusion list
> Press [r/R] to remove elements to an inclusion / exclusion list
> Press [h/H] to display this message
> Press [CTRL] + [c/C] to gracefully exit IoctlHunter

-----------------------------------------------------------
```





