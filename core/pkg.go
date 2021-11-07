package core

import (
	"embed"
	"fmt"
	"io/ioutil"
	"strconv"
)

// 这里定义函数规范

func ReadBin(path string)([]byte,error){
	file, err := ioutil.ReadFile(path)
	if err != nil {
		//fmt.Println(fmt.Sprintf("Open %s is failed",path))
		return []byte{},err
	}
	return file,nil
}

func ReadTemplate(fs embed.FS,path string)(string,error){
	file, err := fs.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(file),err
}
func ReturnKeyRoot(num string)string{
	var root = "static/decryption/"
	switch num {
	case "a":
		return root + "aes.tpl"
	case "b":
		return root + "xor.tpl"
	case "c":
		return root + "base64.tpl"
	default:
		return ""
	}
}

func EncryptoCode(num string,raw []byte,key string)(string){
	switch num {
	case "a": // aes编码
		if len(key) != 16 {
			fmt.Println("[-] You need a 16-bit key")
			return ""
		}
		keys,_:= EncryptByAes(raw,[]byte(key))
		fmt.Println(fmt.Sprintf("[+] Use aes to encrypt shellcode,key is %s",key))
		return keys // 返回一个base64编码后的aes加密字符出
	case "b": // xor编码
		n, err := strconv.Atoi(key)
		if err != nil {
			fmt.Println("[-] You need xor key,it is a number")
			return ""
		}
		keys, _ := EncryptXor(raw,n)
		fmt.Println(fmt.Sprintf("[+] Use xor to encrypt shellcode,xor number %s",key))
		return keys
	case "c":
		keys,_ := EncryptBase64(raw,0)
		fmt.Println(fmt.Sprintf("[+] Use base64 to encrypt shellcode,not need key"))
		return keys
	case "d":
		return ""
	default:
		return ""
	}
}
