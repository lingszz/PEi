package UPXBypass

import (
	"PEi/PEedit"
	"log"
	"os"
)

func Run(filename string, outname string) {
	fileBytes, err := os.ReadFile(filename)
	if err != nil {
		log.Panicf("读取文件异常 %s", err)
	}
	// fmt.Printf("fileBytes: %v\n", fileBytes)
	PE := PEedit.GetPeAddress(fileBytes)
	NewFileBytes := PEedit.WriteUPX(fileBytes, PE)
	NewFileBytes = PEedit.WriteUPXPE(NewFileBytes, PE)
	os.WriteFile(outname, NewFileBytes, 0644)
}
