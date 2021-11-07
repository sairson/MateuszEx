func AesDecrypt(data []byte,key []byte)([]byte){
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	crypted := make([]byte, len(data))
	blockMode.CryptBlocks(crypted, data)
	crypted, err = pkcs7UnPadding(crypted)
	if err != nil {
		return nil
	}
	return crypted
}

func pkcs7UnPadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("加密字符串错误！")
	}
	//获取填充的个数
	unPadding := int(data[length-1])
	return data[:(length - unPadding)], nil
}

func Aes(data string,Pwdkey string) []byte {
	dataByte, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil
	}
	return AesDecrypt(dataByte, []byte(Pwdkey))
}

func Crypto(payload string)[]byte{
	return Aes(payload,{{key}})
}