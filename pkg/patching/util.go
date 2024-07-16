package patching

import (
	"bytes"
	"encoding/binary"
	"net"
)

func packAddress(target net.IP, port uint16) []byte {
	ipBytes := []byte(target.To4())

	sockAddr := &bytes.Buffer{}
	binary.Write(sockAddr, binary.BigEndian, port)
	binary.Write(sockAddr, binary.BigEndian, ipBytes)

	return sockAddr.Bytes()
}
