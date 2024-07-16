package patching

import (
	"crypto/aes"
	"crypto/cipher"
	_ "embed"
	"fmt"
	"net"
	"strings"
)

//go:embed dist/client
var clientData []byte

var CLIENT_PATCH_CONNECT_ADDR = []byte("PATCH_CONNECT_ADDR_HERE")

var CLIENT_PATCH_SERVER_CERT = []byte(strings.Repeat("A", 1000))
var CLIENT_PATCH_CLIENT_CERT = []byte(strings.Repeat("B", 1000))
var CLIENT_PATCH_CLIENT_KEY = []byte(strings.Repeat("C", 500))

func padPatch(orig []byte, patch []byte) []byte {
	if len(patch) > len(orig) {
		panic("patch is too long")
	}

	padding := []byte(strings.Repeat(" ", len(orig)-len(patch)))
	return append(patch, padding...)
}

func padAndPatch(data []byte, search []byte, repl []byte) []byte {
	return PatchBinary(data, search, padPatch(search, repl))
}

func PatchAndEncryptClient(target net.IP, port uint16, serverCert []byte, clientCert []byte, clientKey []byte, encryptionKey []byte) ([]byte, error) {
	ipStr := fmt.Sprintf("%v:%v", target.String(), port)

	patched := padAndPatch(clientData, CLIENT_PATCH_CONNECT_ADDR, []byte(ipStr))

	patched = padAndPatch(patched, CLIENT_PATCH_SERVER_CERT, serverCert)
	patched = padAndPatch(patched, CLIENT_PATCH_CLIENT_CERT, clientCert)
	patched = padAndPatch(patched, CLIENT_PATCH_CLIENT_KEY, clientKey)

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ct := gcm.Seal(patched[:0], []byte("IVCANBECONST"), patched, []byte(""))

	return ct, nil
}
