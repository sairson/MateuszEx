package core

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
)

// aes加密

func AesEncrypt(data []byte, key []byte) ([]byte, error) {
	//创建加密实例
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	//判断加密快的大小
	blockSize := block.BlockSize()
	//填充
	encryptBytes := pkcs7Padding(data, blockSize)
	//初始化加密数据接收切片
	crypted := make([]byte, len(encryptBytes))
	//使用cbc加密模式
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	//执行加密
	blockMode.CryptBlocks(crypted, encryptBytes)
	return crypted, nil
}

func pkcs7Padding(data []byte, blockSize int) []byte {
	//判断缺少几位长度。最少1，最多 blockSize
	padding := blockSize - len(data)%blockSize
	//补足位数。把切片[]byte{byte(padding)}复制padding个
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}


//EncryptByAes Aes加密 后 base64 再加
func EncryptByAes(data []byte,PwdKey []byte) (string, error) {
	res, err := AesEncrypt(data, PwdKey)
	//fmt.Println(err)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(res), nil
}


// xor 加密

func EncryptXor(data []byte,num int)(string, error){
	var shellcode string
	var shellcode_size = 0
	for _,value := range data{
		base10 := int(value) ^ num
		code_hex := hex.EncodeToString(IntToBytes(base10))
		if len(code_hex) == 1{
			code_hex = "0" + code_hex
		}
		shellcode += "\\x" + code_hex
		shellcode_size += 1
	}
	return shellcode,nil
}

func IntToBytes(n int)[]byte{
	x := int32(n)
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.BigEndian, x)
	return bytesBuffer.Bytes()[3:]
}


func EncryptBase64(data []byte,num int)(string, error){
	sEnc := base64.StdEncoding.EncodeToString([]byte(data))
	return sEnc,nil
}