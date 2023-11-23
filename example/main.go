package main

import (
	"fmt"
	"os"
	"strconv"

	driverutils "example/driver_utils"

	"golang.org/x/sys/windows"
)

func main() {
	if len(os.Args) != 6 {
		fmt.Println("Usage: go run main.go full_driver_path service_name device_name IOCTL PID")
		return
	}

	driverPath := os.Args[1]
	svcName := os.Args[2]
	deviceName := os.Args[3]
	ioctlCode, _ := strconv.ParseUint(os.Args[4], 10, 32)
	pid, _ := strconv.ParseUint(os.Args[5], 10, 32)

	if err := driverutils.ElevatePrivileges(); err != nil {
		fmt.Println("Error when elevating privileges", err)
		return
	}

	if err := driverutils.LoadDriver(driverPath, svcName); err != nil {
		fmt.Println("Driver loading error:", err)
		if err := driverutils.UnloadDriver(svcName); err != nil {
			fmt.Println("Driver unloading error:", err)
			return
		}
		fmt.Println("Driver unloaded")
		return
	}

	deviceHandle, err := driverutils.OpenDevice(deviceName)
	if err != nil {
		fmt.Println("Device opening error:", err)
		return
	}

	_, err = driverutils.DeviceIOControl(deviceHandle, uint32(ioctlCode), uint32(pid))
	if err != nil {
		fmt.Println("Error when sending the IOCTL:", err)
	} else {
		fmt.Println("Driver loaded and successful IOCTL call.")
	}

	if err := windows.CloseHandle(deviceHandle); err != nil {
		fmt.Printf("Error when closing the handle: %v\n", err)
	}

	if err := driverutils.UnloadDriver(svcName); err != nil {
		fmt.Println("Error when unloading the driver:", err)
	}

	return
}
