package patching

import (
	"fmt"
)

const NUMROUNDS = 32

func TreyferCBCMac(text []byte, key []byte, iv []byte) ([]byte, error) {
	if len(text)%8 != 0 {
		return nil, fmt.Errorf("text has length %v which is not divisible by 8", len(text))
	}

	var err error

	res := iv
	for i := 0; i < len(text); i += 8 {
		curr := text[i : i+8]

		res, err = xor_byte_arrays(res, curr)
		if err != nil {
			return nil, err
		}

		res, err = treyfer_encrypt_block(res, key)
		if err != nil {
			return nil, err
		}
	}

	return res, nil
}

func xor_byte_arrays(a []byte, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, fmt.Errorf("trying to xor byte arrays with different lengths: %v and %v", len(a), len(b))
	}

	c := make([]byte, len(a))

	for i, ai := range a {
		c[i] = ai ^ b[i]
	}

	return c, nil
}

func treyfer_encrypt_block(text []byte, key []byte) ([]byte, error) {
	if len(text) != 8 {
		return nil, fmt.Errorf("invalid text length for block encrypt: %v", len(text))
	}
	if len(key) != 8 {
		return nil, fmt.Errorf("invalid key length for block encrypt: %v", len(key))
	}

	sbox := retrieveSBox()

	res := make([]byte, 8)
	copy(res, text)

	var t uint8 = res[0]
	for i := 0; i < 8*NUMROUNDS; i++ {
		t += key[i%8]
		t = sbox[t] + res[(i+1)%8]
		t = (t << 1) | (t >> 7) /* Rotate left 1 bit */
		res[(i+1)%8] = t
	}

	return res, nil
}
