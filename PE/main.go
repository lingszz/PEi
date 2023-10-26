package PE

import (
	"bytes"
	"encoding/binary"
)

type Editor interface {
	GetCheckSum() uint32
	GetSecurityDirectoryRVA() uint32
	GetSecurityDirectorySizePE() uint32
	GetSecurityDirectorySize() uint32
	WriteSecurityDirectorySizeAndPE(ShellBytesLen uint32) []byte
	WriteCheckSum() []byte
	ShellcodeSteganography(ShellBytes []byte) []byte
}

type X64 struct {
	FileBytes             []byte
	AddressOfNewExeHeader uint32
}

type X86 struct {
	FileBytes             []byte
	AddressOfNewExeHeader uint32
}

func IntToBytesLittleEndian(tmp uint32) []byte {
	bytesBuffer := bytes.NewBuffer([]byte{})
	binary.Write(bytesBuffer, binary.LittleEndian, &tmp)
	return bytesBuffer.Bytes()
}

func GetAddressOfNewExeHeader(fileBytes []byte) uint32 {
	a := uint32(0x3c)
	byteArr := fileBytes[a : a+4]
	data := binary.LittleEndian.Uint32(byteArr)
	return data
}
