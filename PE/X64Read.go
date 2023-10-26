package PE

import (
	"encoding/binary"
)

func (x X64) GetCheckSum() uint32 {
	a := uint32(0x58) + x.AddressOfNewExeHeader
	byteArr := x.FileBytes[a : a+4]
	data := binary.LittleEndian.Uint32(byteArr)
	return data
}

func (x X64) GetSecurityDirectoryRVA() uint32 {
	a := uint32(0xA8) + x.AddressOfNewExeHeader
	byteArr := x.FileBytes[a : a+4]
	data := binary.LittleEndian.Uint32(byteArr)
	return data
}

func (x X64) GetSecurityDirectorySizePE() uint32 {
	a := uint32(0xAC) + x.AddressOfNewExeHeader
	byteArr := x.FileBytes[a : a+4]
	data := binary.LittleEndian.Uint32(byteArr)
	return data
}

func (x X64) GetSecurityDirectorySize() uint32 {
	a := x.GetSecurityDirectoryRVA()
	byteArr := x.FileBytes[a : a+4]
	data := binary.LittleEndian.Uint32(byteArr)
	return data
}
