package Tools

import (
	"log"
	"os"
)

func Xor(NeedCode []byte, key byte) []byte {
	for i := 0; i < len(NeedCode); i++ {
		NeedCode[i] ^= key
	}
	return NeedCode
}

func Invert(NeedCode []byte) []byte {
	for i := 0; i < len(NeedCode); i++ {
		NeedCode[i] = ^NeedCode[i]
	}
	return NeedCode
}

func ShellcodePretreatment(codeName string, outName string, xorCode byte) {
	ShellBytes, err := os.ReadFile(codeName)
	if err != nil {
		log.Panicf("读取文件 %s 异常 %s", codeName, err)
	}
	ShellBytes = Invert(ShellBytes)
	ShellBytes = Xor(ShellBytes, xorCode)
	os.WriteFile(outName, ShellBytes, 0644)
}
