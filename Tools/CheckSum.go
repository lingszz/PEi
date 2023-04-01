package Tools

import (
	"encoding/binary"
	"math"
)

func GeneratePECheckSum(fileBytes []byte) uint32 {
	// get checksum offset
	ntHeaderOffsetBytes := fileBytes[0x3C:0x40]
	ntHeaderOffset := binary.LittleEndian.Uint32(ntHeaderOffsetBytes)
	checksumOffset := ntHeaderOffset + 0x58

	var checksum uint64 = 0
	top := uint64(math.Pow(2, 32))

	for i := 0; i < len(fileBytes)/4; i++ {
		if i == int(checksumOffset/4) {
			continue
		}
		dword := binary.LittleEndian.Uint32(fileBytes[i*4 : (i*4)+4])
		checksum = (checksum & 0xffffffff) + uint64(dword) + (checksum >> 32)
		if checksum > top {
			checksum = (checksum & 0xffffffff) + (checksum >> 32)
		}
	}

	checksum = (checksum & 0xffff) + (checksum >> 16)
	checksum = (checksum) + (checksum >> 16)
	checksum = checksum & 0xffff

	checksum += uint64(len(fileBytes))
	return uint32(checksum)
}
