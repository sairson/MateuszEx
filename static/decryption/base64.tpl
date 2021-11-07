func Base64(shellcode string,key int)[]byte{
	sDec, err := base64.StdEncoding.DecodeString(shellcode)
	if err != nil {
		return []byte{}
	}
	return sDec
}

func Crypto(payload string)[]byte{
	return Base64(payload,{{key}})
}
