# IoctlHunter

IoctlHunter is a command line tool allowing to ease the analysis of IOCTL calls made by userland software in destination of Windows drivers.

From cybersecurity perspective, this allows security researchers to look for IOCTLs calls that could be re-used in standalone binaries to perform various actions such as EoP or EDR disabling.

A blog post demonstrating this usage will be published soon.

## Instalation

IoctlHunter can be simply installed via the public PyPi repository as following:
```
pip install ioctlhunter
```

Note that this tools is dedicated to be used on Windows environments to analyse specific process / binaries interacting with drivers.

## Usage

Unlike many of today's tools, IoctlHunter allows dynamic analysis of interactions between a process and potential drivers thanks to [Frida](https://frida.re/).

Indeed, unlike static driver analysis approaches, the aim of the tool is to execute the binary and browse the various options in order to consult the IOCTL calls that have taken place within IoctlHunter.

The mindset to adopt when using IoctlHunter is a bit like using BurpSuite to analyze a website. You navigate to the options that might interest you and look in IoctlHunter for the potential associated IOCTL.

The tool provides several essential pieces of information to replay an IOCTL thanks to the `DeviceIoContol` function (see [MS documentation](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-deviceiocontrol)):
- The target driver ;
- The IOCTL code transmitted (dwIoControlCode) ;
- The associated data transmitted (lpInBuffer) and size (nInBufferSize);
- Returned data (lpOutBuffer, nOutBufferSize).

From this information, it is possible to statically analyze the driver in order to analyze the associated code in detail, starting from the IOCTL code. However, it is also possible to directly replay this IOCTL call if its use seems obvious.

Successful use of IoctlHunter will enable RedTeamers / Pentesters to build a stand-alone executable installing a specific driver and making one or more IOCTL calls to it in order to perform various tasks. The advantage is obviously to execute signed drivers with kernel privileges and useful features.

## Command line options

IoctlHunter is usable as a classic CLI tool. Moreover, dynamic key binding are available to ease the analysis during the execution of the targeted process / binary (press H at runtime).

Find below the actually available options:

```

     _____           _   _    _    _             _
    |_   _|         | | | |  | |  | |           | |
      | |  ___   ___| |_| |  | |__| |_   _ _ __ | |_ ___ _ __
      | | / _ \ / __| __| |  |  __  | | | | '_ \| __/ _ \ '__|
     _| || (_) | (__| |_| |  | |  | | |_| | | | | ||  __/ |
    |_____\___/ \___|\__|_|  |_|  |_|\__,_|_| |_|\__\___|_|
    v0.1


usage: IoctlHunter [-h] [-v] [-ts] (-e EXE | -p PID) [-a ARGS [ARGS ...]] [-x32] [-eio EXCLUDED_IOCTLS [EXCLUDED_IOCTLS ...]] [-iio INCLUDED_IOCTLS [INCLUDED_IOCTLS ...]] [-edrv EXCLUDED_DRIVERS [EXCLUDED_DRIVERS ...]]    
                   [-idrv INCLUDED_DRIVERS [INCLUDED_DRIVERS ...]] [-eho] [-hos] [-as] [-o OUTPUT]

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
=======
# IoctlHunter
>>>>>>> 0f40c5b0d238fcba9d70e4d50a3f75f462748b9a
