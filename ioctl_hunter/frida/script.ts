//
// *LoadDriver symbols
//

var ZwLoadDriver = Module.findExportByName("ntdll.dll", 'ZwLoadDriver')
var NtLoadDriver = Module.findExportByName("ntdll.dll", 'NtLoadDriver')

//
// *DeviceIoControl symbols
//

var DeviceIoControl_kernel32 = Module.findExportByName("kernel32.dll", 'DeviceIoControl')
var DeviceIoControl_kernelbase = Module.findExportByName("kernelbase.dll", 'DeviceIoControl')
var NtDeviceIoControlFile = Module.findExportByName("ntdll.dll", 'NtDeviceIoControlFile')
var ZwDeviceIoControlFile = Module.findExportByName("ntdll.dll", 'ZwDeviceIoControlFile')


//
// *CreateFile* symbols
//

var CreateFileW_kernel32 = Module.findExportByName("kernel32.dll", 'CreateFileW')
var CreateFileW_kernelbase = Module.findExportByName("kernelbase.dll", 'CreateFileW')
var CreateFileA_kernel32 = Module.findExportByName("kernel32.dll", 'CreateFileA')
var CreateFileA_kernelbase = Module.findExportByName("kernelbase.dll", 'CreateFileA')
var ZwCreateFile = Module.findExportByName("ntdll.dll", 'ZwCreateFile')
var NtCreateFile = Module.findExportByName("ntdll.dll", 'NtCreateFile')

//
// *RegSetValue* symbols
//

var RegSetValueExW_advapi32 = Module.findExportByName("Advapi32.dll", 'RegSetValueExW')

//
// Dynamically called functions prototypes
//

var Exp_GetFinalPathNameByHandleW = Module.findExportByName("kernel32.dll", 'GetFinalPathNameByHandleW')
var Func_GetFinalPathNameByHandleW = new NativeFunction(Exp_GetFinalPathNameByHandleW, 'int', ['int', 'pointer', 'int', 'int'])

var Exp_NtQueryObject = Module.findExportByName("ntdll.dll", 'NtQueryObject')
var Func_NtQueryObject = new NativeFunction(Exp_NtQueryObject, 'int', ['int', 'int', 'pointer', 'int', 'pointer'])

//
// Global variables
//

var x32 = false
var all_symbols = false
var hook_enabled = false
var excluded_ioctl = []
var loaded_drivers = {}
var queue_loaded_drivers = []
var queue_device_ioctl = []
var open_handles = {}

//
// RPC functions
//

rpc.exports = {
    excludeioctl: function (ioctl) {
        excluded_ioctl.push(ioctl);
        return excluded_ioctl;
    },
    sethookenabled: function (bool) {
        hook_enabled = bool;
    },
    is32bits: function (bool) {
        x32 = bool;
    },
    isallsymbols: function (bool) {
        all_symbols = bool;
    },
    getqueuedeviceioctl: function () {
        let tmp_queue = queue_device_ioctl;
        queue_device_ioctl = [];
        return tmp_queue;
    },
    getqueueloadeddrivers: function () {
        let tmp_queue = queue_loaded_drivers;
        queue_loaded_drivers = [];
        return tmp_queue;
    },
    getopenhandles: function () {
        return open_handles;
    },
};

//
// Generic functions
//

function getPathByHandle(handle) {
    var ptr = Memory.alloc(2048)
    var ptr2 = Memory.alloc(2048)
    var ret = Func_NtQueryObject(handle, 1, ptr, 1024, ptr2)

    if (x32) {
        var path = Memory.readUtf16String(Memory.readPointer(ptr.add(8)))   // 32 bits binaries
    }
    else {
        var path = Memory.readUtf16String(Memory.readPointer(ptr.add(16)))  // 64 bits binaries
    }

    return path.replaceAll("\\", "\\\\")
}

//
// *LoadDriver* interceptors
//

function LoadDriver_Manager(args) {
    if (x32) {
        var loaded_driver = args[0].add(24).readUtf16String()   // 32 bits binaries
    }
    else {
        var loaded_driver = args[0].add(16).readUtf16String()   // 64 bits binaries
    }
    var tmp_driver_name = loaded_driver.toLowerCase().split("\\")

    if (loaded_driver.toLowerCase().endsWith(".sys")) {
        var driver_name = tmp_driver_name[tmp_driver_name.length - 1].replace(".sys", "")
    }
    else {
        var driver_name = tmp_driver_name[tmp_driver_name.length - 1]
    }

    if (driver_name in loaded_drivers) {
        loaded_drivers[driver_name].loaded = true
        queue_loaded_drivers.push(loaded_drivers[driver_name])
        return true
    }

    return false
}

Interceptor.attach(ZwLoadDriver, {
    onEnter(args) {
        LoadDriver_Manager(args)
    },
});


Interceptor.attach(NtLoadDriver, {
    onEnter(args) {
        if (all_symbols) {
            LoadDriver_Manager(args)
        }
    },
});


//
// *DeviceIoControl Interceptors
//


function DeviceIoControl_Manager(symbol_src, args, is_kernel_libs) {
    if (is_kernel_libs) {
        var handle_device = args[0].toUInt32()
        var ioctl = args[1].toUInt32()
        var buff_in_addr = args[2]
        var buff_in_size = args[3].toUInt32()
        var buff_out_addr = args[4]
        var buff_out_size = args[5].toUInt32()
        var bytes_returned = Memory.readU32(args[6])
    }
    else {
        var handle_device = args[0].toUInt32()
        var ioctl = args[5].toUInt32()
        var buff_in_addr = args[6]
        var buff_in_size = args[7].toUInt32()
        var buff_out_addr = args[8]
        var buff_out_size = args[9].toUInt32()
        var bytes_returned = ''
    }

    let hex_in = hexdump(buff_in_addr, {
        offset: 0,
        length: buff_in_size,
        header: true,
        ansi: false
    })
    let hex_out = hexdump(buff_out_addr, {
        offset: 0,
        length: buff_out_size,
        header: true,
        ansi: false
    })

    if (hook_enabled && !(excluded_ioctl.includes(ioctl))) {
        let params = '{' +
            ' "symbol":"' + symbol_src + '", ' +
            ' "handle_device":"' + handle_device + '", ' +
            ' "handle_path":"' + getPathByHandle(handle_device) + '", ' +
            ' "ioctl":"' + ioctl + '", ' +
            ' "buff_in": { ' +
            ' "size":"' + buff_in_size + '", ' +
            ' "hexdump":"' + encodeURI(hex_in) + '" ' +
            ' }, ' +
            ' "buff_out": { ' +
            ' "size":"' + buff_out_size + '", ' +
            ' "bytes_returned":"' + bytes_returned + '", ' +
            ' "hexdump":"' + encodeURI(hex_out) +
            '" } } ';

        queue_device_ioctl.push(params)
        return true
    }
    return false
}


Interceptor.attach(NtDeviceIoControlFile, {
    onEnter(args) {
        if (all_symbols) {
            var symbol_src = 'NtDeviceIoControlFile (ntdll.dll)'
            DeviceIoControl_Manager(symbol_src, args, false)
        }
    },
});

Interceptor.attach(ZwDeviceIoControlFile, {
    onEnter(args) {
        var symbol_src = 'ZwDeviceIoControlFile (ntdll.dll)'
        DeviceIoControl_Manager(symbol_src, args, false)
    },
});

Interceptor.attach(DeviceIoControl_kernel32, {
    onEnter(args) {
        if (all_symbols) {
            var symbol_src = 'DeviceIoControl (kernel32.dll)'
            DeviceIoControl_Manager(symbol_src, args, true)
        }
    },
});

Interceptor.attach(DeviceIoControl_kernelbase, {
    onEnter(args) {
        if (all_symbols) {
            var symbol_src = 'DeviceIoControl (kernelbase.dll)'
            DeviceIoControl_Manager(symbol_src, args, true)
        }
    },
});

//
// *CreateFile* Interceptors
//

function ZwNt_CreateFile_Manager(args) {
    if (x32) {
        // 32 bits binaries
        // Pointer to OBJECT_ATTRIBUTES (ObjectAttributes) -> +8 PUNICODE_STRING (ObjectName) -> +4 PWSTR (Buffer)
        var path = args[2].add(8).readPointer().add(4).readPointer().readUtf16String()
    }
    else {
        // 64 bits binaries
        // Pointer to OBJECT_ATTRIBUTES (ObjectAttributes) -> +16 PUNICODE_STRING (ObjectName) -> +8 PWSTR (Buffer)
        var path = args[2].add(16).readPointer().add(8).readPointer().readUtf16String()
    }
    var handle = args[0].readPointer().toUInt32()
    if (((path.toLowerCase().startsWith('\\??\\')) && !(path.toLowerCase().startsWith('\\??\\c:'))) || (path.toLowerCase().startsWith('\\device\\')) || (path.toLowerCase().endsWith('.sys'))) {
        open_handles[handle] = path
    };
    return true
}

function Commons_CreateFile_OnEnter_Manager(this_cpy, args, isAnsi) {
    this_cpy.match = false

    if (isAnsi) {
        this_cpy.path = Memory.readAnsiString(args[0])
    }
    else {
        this_cpy.path = Memory.readUtf16String(args[0])
    }

    if (this_cpy.path.startsWith('\\')) {
        this_cpy.match = true
    };

    return true;
}

function Commons_CreateFile_OnLeave_Manager(this_cpy, retval) {
    if (this_cpy.match) {
        var handle = retval.toUInt32()
        open_handles[handle] = this_cpy.path
    };
    return true;
}

/*Interceptor.attach(ZwCreateFile, {
    onEnter(args) {
        ZwNt_CreateFile_Manager(args)
    },
});*/

/*Interceptor.attach(NtCreateFile, {
    onEnter(args) {
        if (all_symbols) {
            ZwNt_CreateFile_Manager(args)
        }
    },
});*/

Interceptor.attach(CreateFileW_kernel32, {
    onEnter(args) {
        Commons_CreateFile_OnEnter_Manager(this, args, false)
    },
    onLeave(retval) {
        Commons_CreateFile_OnLeave_Manager(this, retval)
    }
});

Interceptor.attach(CreateFileW_kernelbase, {
    onEnter(args) {
        Commons_CreateFile_OnEnter_Manager(this, args, false)
    },
    onLeave(retval) {
        Commons_CreateFile_OnLeave_Manager(this, retval)
    }
});

Interceptor.attach(CreateFileA_kernel32, {
    onEnter(args) {
        Commons_CreateFile_OnEnter_Manager(this, args, true)
    },
    onLeave(retval) {
        Commons_CreateFile_OnLeave_Manager(this, retval)
    }
});

Interceptor.attach(CreateFileA_kernelbase, {
    onEnter(args) {
        Commons_CreateFile_OnEnter_Manager(this, args, true)
    },
    onLeave(retval) {
        Commons_CreateFile_OnLeave_Manager(this, retval)
    }
});

//
// *RegSetValue* Interceptors
//

Interceptor.attach(RegSetValueExW_advapi32, {
    onEnter(args) {
        if (args[1].readUtf16String().includes("ImagePath")) {
            var img_pth = args[4].readUtf16String()
            var cur_hkey = getPathByHandle(args[0].toUInt32())
            if (cur_hkey.toLowerCase().includes("controlset")) {
                var tmp_driver_name = cur_hkey.toLowerCase().split("services\\")
                var driver_name = tmp_driver_name[tmp_driver_name.length - 1]

                if (!(driver_name in loaded_drivers)) {
                    loaded_drivers[driver_name] = { name: driver_name, key: cur_hkey, image_path: img_pth, loaded: false }
                }
            }
        }
    },
});