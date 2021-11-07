func xor(shellcode []byte,key byte)[]byte{
	for i :=0;i<len(shellcode);i++ {
		shellcode[i] ^= key
	}
	return shellcode
}

func Crypto(payload string)[]byte{
	shellcode := []byte(payload)
	return xor(shellcode,{{key}})
}
