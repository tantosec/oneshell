package pkg

import (
	"bytes"
	"fmt"
)

var PRINTABLE = []byte("0123456789abcdefghijklmnopqrstuvwyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&()*+,-./:;<=>?@[]^_`{|}~")
var NUMERIC = []byte("0123456789")

func EchoifyData(data []byte) string {
	// TODO: We can reduce size using shell variables, for example:
	// echo aaaaaabaaaaaa
	// x=aaaaaa;echo ${x}b$x
	// x=aaa;echo $x${x}b$x$x    # this case is longer, is this always so?

	// By creating an alias for echo and using octal notation we can create an echo command
	//   that works on every shell.

	// Note: this adds a newline but that's fine for our use.
	result := "zy(){ if [ `echo -e` ];then echo \"$1\";else echo -e \"$1\";fi;};zy '"

	prev_escaped := false

	for _, val := range data {
		if bytes.ContainsRune(PRINTABLE, rune(val)) && (!bytes.ContainsRune(NUMERIC, rune(val)) || !prev_escaped) {
			result += string(rune(val))
			prev_escaped = false
		} else {
			if val == 0 {
				result += "\\0"
			} else {
				result += fmt.Sprintf("\\0%o", val)
			}
			prev_escaped = true
		}
	}

	result += "'"

	return result
}

func RunEchoifiedBinary(data []byte) string {
	return fmt.Sprintf("%v>/tmp/z;chmod +x /tmp/z;/tmp/z", EchoifyData(data))
}
