package PE

import (
	"encoding/binary"
)

func (x X86) GetCheckSum() uint32 {
	a := uint32(0x58) + x.AddressOfNewExeHeader
	byteArr := x.FileBytes[a : a+4]
	data := binary.LittleEndian.Uint32(byteArr)
	return data
}

func (x X86) GetSecurityDirectoryRVA() uint32 {
	a := uint32(0x98) + x.AddressOfNewExeHeader
	byteArr := x.FileBytes[a : a+4]
	data := binary.LittleEndian.Uint32(byteArr)
	return data
}

func (x X86) GetSecurityDirectorySizePE() uint32 {
	a := uint32(0x9C) + x.AddressOfNewExeHeader
	byteArr := x.FileBytes[a : a+4]
	data := binary.LittleEndian.Uint32(byteArr)
	return data
}

func (x X86) GetSecurityDirectorySize() uint32 {
	a := x.GetSecurityDirectoryRVA()
	byteArr := x.FileBytes[a : a+4]
	data := binary.LittleEndian.Uint32(byteArr)
	return data
}
