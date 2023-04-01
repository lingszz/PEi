package PEedit

import (
	"bytes"
	"encoding/binary"
	"log"
)

func IntToBytesLittleEndian(tmp uint32) []byte {
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.LittleEndian, &tmp)
	return bytesBuffer.Bytes()
}

func WriteSecurityDirectorySizeAndPE(fileBytes []byte, PE uint32, ShellBytesLen uint32) []byte {
	WeNeedSize := IntToBytesLittleEndian(GetSecurityDirectorySize(fileBytes, PE) + ShellBytesLen)
	if len(WeNeedSize) != 4 {
		log.Panicf("在依据ShellBytesLen的大小对SecurityDirectorySize做出更改时我们需要的Byte位不等于4位[与预期的DWORD不符]")
	}
	SecurityDirectoryRVA := GetSecurityDirectoryRVA(fileBytes, PE)
	for i := 0; i < 4; i++ {
		fileBytes[SecurityDirectoryRVA+uint32(i)] = WeNeedSize[i]
		fileBytes[uint32(0x9C)+PE+uint32(i)] = WeNeedSize[i]
	}
	return fileBytes
}

func WriteCheckSum(fileBytes []byte, PE uint32, NewCheckSum uint32) []byte {
	WeNeedCheckSum := IntToBytesLittleEndian(NewCheckSum)
	for i := 0; i < 4; i++ {
		fileBytes[uint32(0x58)+PE+uint32(i)] = WeNeedCheckSum[i]
	}
	return fileBytes
}

func WriteUPX(fileBytes []byte, PE uint32) []byte {
	listA := GetSectionHeaderAddressAll(fileBytes, PE)
	if len(listA) < 2 {
		log.Panic("当前文件可能不是UPX文件, Section Header 的值小于2")
	}
	text := []byte{0x2e, 0x74, 0x65, 0x78, 0x74, 0x00, 0x00, 0x00}
	data := []byte{0x2e, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x00}
	upx0 := listA[0]
	upx1 := listA[1]
	upx2 := GetFirstSectionHeaderRawAddress(fileBytes, PE)
	for i := 0; i < 8; i++ {
		fileBytes[upx0+uint32(i)] = text[i]
		fileBytes[upx1+uint32(i)] = data[i]
	}
	for i := 1; i < 8*5+1; i++ {
		fileBytes[upx2-uint32(i)] = 0x00
	}
	return fileBytes
}

func WriteUPXPE(fileBytes []byte, PE uint32) []byte {
	UPX2Address := GetFirstSectionHeaderRawAddress(fileBytes, PE)
	NewPeAddress := []byte{0x50, 0x00, 0x00, 0x00}
	Pe := GetPE(fileBytes, PE)
	for i := 0; i < int(UPX2Address-0x40); i++ {
		fileBytes[0x40+i] = 0x00
	}
	for i := 0; i < len(Pe); i++ {
		fileBytes[int(NewPeAddress[0])+i] = Pe[i]
	}
	for i := 0; i < 4; i++ {
		fileBytes[0x3c+i] = NewPeAddress[i]
	}
	return fileBytes
}
