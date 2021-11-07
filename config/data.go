package config


var TEMPLATE_STATIC_DATA TEMPLATE_NT_YAML // 定义template读取的结构体变量


type TEMPLATE_NT_YAML struct {
	Template []struct {
		Name     string `yaml:"Name"`
		Template string `yaml:"Template"`
		Module   string `yaml:"Module"`
	} `yaml:"template"`
}


type SHELLCODE_DATA struct {
	Shellcode string
	Key string
}