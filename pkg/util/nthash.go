package util

import (
	"encoding/binary"
	"encoding/hex"
	"golang.org/x/crypto/md4"
	"unicode/utf16"
)

// refer:https://cybersecurity.ink/posts/golang-ntlmhash/
func Md5UTF16toToLittleEndian(passVal string) string {
	encoded_pass := utf16.Encode([]rune(passVal))
	passVal2 := convertUTF16ToLittleEndianBytes(encoded_pass)
	return md4toHexadecimal(passVal2)
}

func md4toHexadecimal(passVal2 []byte) string {
	passVal3 := md4.New()
	passVal3.Write(passVal2)
	return hex.EncodeToString(passVal3.Sum(nil))
}

func convertUTF16ToLittleEndianBytes(a []uint16) []byte {
	passVal2 := make([]byte, 2*len(a))
	for index, value := range a {
		binary.LittleEndian.PutUint16(passVal2[index*2:], value)
	}
	return passVal2
}