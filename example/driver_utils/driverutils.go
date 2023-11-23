package driverutils

import (
	"encoding/base64"
	"encoding/binary"
	"syscall"
	"time"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

const (
	SeLoadDriverPrivilege = "SeLoadDriverPrivilege"
)

var (
	kernel32              = syscall.NewLazyDLL("kernel32.dll")
	advapi32              = syscall.NewLazyDLL("advapi32.dll")
	createFile            = kernel32.NewProc("CreateFileW")
	deviceIoControl       = kernel32.NewProc("DeviceIoControl")
	openProcessToken      = advapi32.NewProc("OpenProcessToken")
	adjustTokenPrivileges = advapi32.NewProc("AdjustTokenPrivileges")
)

func ElevatePrivileges() error {
	var tokenHandle windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tokenHandle)
	if err != nil {
		return err
	}

	privilegeName := utf16.Encode([]rune("SeLoadDriverPrivilege"))
	privilegeNamePtr := &privilegeName[0]
	var luid windows.LUID
	err = windows.LookupPrivilegeValue(nil, privilegeNamePtr, &luid)
	if err != nil {
		return err
	}

	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{
				Luid:       luid,
				Attributes: windows.SE_PRIVILEGE_ENABLED,
			},
		},
	}

	err = windows.AdjustTokenPrivileges(tokenHandle, false, &tp, 0, nil, nil)
	if err != nil {
		return err
	}

	return nil
}

func LoadDriver(driverPath string, svcName string) error {
	scManager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CREATE_SERVICE)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(scManager)

	driverPathPtr, err := windows.UTF16PtrFromString(driverPath)
	if err != nil {
		return err
	}

	serviceDisplayName, err := windows.UTF16PtrFromString(svcName)
	serviceName, err := windows.UTF16PtrFromString(svcName)

	service, err := windows.CreateService(
		scManager,
		serviceName,
		serviceDisplayName,
		windows.SERVICE_ALL_ACCESS,
		windows.SERVICE_KERNEL_DRIVER,
		windows.SERVICE_DEMAND_START,
		1,
		driverPathPtr,
		nil,
		nil,
		nil,
		nil,
		nil,
	)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(service)

	err = windows.StartService(service, 0, nil)
	if err != nil {
		return err
	}

	return nil
}

func UnloadDriver(svcName string) error {
	scManager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ALL_ACCESS)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(scManager)

	serviceName, err := windows.UTF16PtrFromString(svcName)
	if err != nil {
		return err
	}

	service, err := windows.OpenService(scManager, serviceName, windows.SERVICE_QUERY_STATUS|windows.SERVICE_STOP|windows.DELETE)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(service)

	serviceStatus := windows.SERVICE_STATUS{}
	err = windows.ControlService(service, windows.SERVICE_CONTROL_STOP, &serviceStatus)
	if err != nil {
		return err
	}

	for {
		err = windows.QueryServiceStatus(service, &serviceStatus)
		if err != nil {
			return err
		}

		if serviceStatus.CurrentState == windows.SERVICE_STOPPED {
			break
		}
		time.Sleep(1 * time.Second)
	}

	err = windows.DeleteService(service)
	if err != nil {
		return err
	}

	return nil
}

func OpenDevice(deviceName string) (windows.Handle, error) {
	deviceHandle, err := windows.CreateFile(
		windows.StringToUTF16Ptr("\\\\.\\\\"+deviceName),
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)

	if err != nil {
		return windows.InvalidHandle, err
	}

	return deviceHandle, nil
}

func DeviceIOControl(deviceHandle windows.Handle, ioctl uint32, pid uint32) (string, error) {
	bufferOutSize := 2048
	bufferOut := make([]byte, bufferOutSize)

	pidBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(pidBytes, uint32(pid))

	var bytesReturned uint32
	err := windows.DeviceIoControl(
		deviceHandle,
		ioctl,
		&pidBytes[0],
		uint32(len(pidBytes)),
		&bufferOut[0],
		uint32(len(bufferOut)),
		&bytesReturned,
		nil,
	)

	if err != nil {
		return "", err
	}

	bufferOutBase64 := base64.StdEncoding.EncodeToString(bufferOut[:bytesReturned])

	return bufferOutBase64, nil
}
