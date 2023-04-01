package PEedit

import (
	"encoding/binary"
)

func GetPeAddress(fileBytes []byte) uint32 {
	a := uint32(0x3c)
	byteArr := fileBytes[a : a+4]
	data := binary.LittleEndian.Uint32(byteArr)
	return data
}

func GetCheckSum(fileBytes []byte, PE uint32) uint32 {
	a := uint32(0x58) + PE
	byteArr := fileBytes[a : a+4]
	data := binary.LittleEndian.Uint32(byteArr)
	return data
}

func GetSecurityDirectoryRVA(fileBytes []byte, PE uint32) uint32 {
	a := uint32(0x98) + PE
	byteArr := fileBytes[a : a+4]
	data := binary.LittleEndian.Uint32(byteArr)
	return data
}

func GetSecurityDirectorySizePE(fileBytes []byte, PE uint32) uint32 {
	a := uint32(0x9C) + PE
	byteArr := fileBytes[a : a+4]
	data := binary.LittleEndian.Uint32(byteArr)
	return data
}

func GetSecurityDirectorySize(fileBytes []byte, PE uint32) uint32 {
	a := GetSecurityDirectoryRVA(fileBytes, PE)
	byteArr := fileBytes[a : a+4]
	data := binary.LittleEndian.Uint32(byteArr)
	return data
}

// 获取 Section Header 中首段 RAW Address的偏移地址
func GetFirstSectionHeaderRawAddress(fileBytes []byte, PE uint32) uint32 {
	a := uint32(0xF8+0x14) + PE
	byteArr := fileBytes[a : a+4]
	data := binary.LittleEndian.Uint32(byteArr)
	return data
}

func GetSectionHeaderAddressAll(fileBytes []byte, PE uint32) []uint32 {
	var listA []uint32
	SizeOfSectionHeader := uint32(0x28)
	FirstSectionHeaderRawAddress := GetFirstSectionHeaderRawAddress(fileBytes, PE)
	a := uint32(0xF8) + PE
	for a <= FirstSectionHeaderRawAddress-SizeOfSectionHeader {
		b := fileBytes[int(a+0x14) : int(a+0x14)+4]
		c := 0
		for i := 0; i < 4; i++ {
			if b[i] == 0x00 {
				c += 1
			}
		}
		if c == 4 {
			break
		}
		listA = append(listA, a)
		a += SizeOfSectionHeader
	}
	return listA
}

func GetSectionHeaderAll(fileBytes []byte, PE uint32) [][]byte {
	var listB [][]byte
	listA := GetSectionHeaderAddressAll(fileBytes, PE)
	for _, a := range listA {
		byteArr := fileBytes[a : a+8]
		listB = append(listB, byteArr)
	}
	return listB
}

func GetPE(fileBytes []byte, PE uint32) []byte {
	var byteArr []byte
	listA := GetSectionHeaderAddressAll(fileBytes, PE)
	byteArr = append(byteArr, fileBytes[PE:listA[len(listA)-1]+uint32(0x28)]...)
	return byteArr
}
