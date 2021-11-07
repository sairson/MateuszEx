package main

import (
	"encoding/base64"
	"fmt"
)

func Base64(shellcode string,key int)[]byte{
	sDec, err := base64.StdEncoding.DecodeString(shellcode)
	if err != nil {
		fmt.Printf("Error decoding string: %s ", err.Error())
		return []byte{}
	}
	return sDec
}

func Crypto(payload string)[]byte{
	shellcode := []byte(payload)
	return Base64(shellcode,{{key}})
}
