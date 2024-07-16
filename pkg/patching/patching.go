package patching

import (
	"bytes"
	"log"
)

func PatchBinary(binary []byte, search []byte, replace []byte) []byte {
	if len(search) != len(replace) {
		log.Fatalf("invalid patch: len(%v) != len(%v)", search, replace)
	}

	firstMatch := bytes.Index(binary, search)
	if bytes.Contains(binary[firstMatch+1:], search) {
		log.Fatalf("invalid patch: %v appears twice in binary", search)
	}

	return bytes.Replace(binary, search, replace, 1)
}
