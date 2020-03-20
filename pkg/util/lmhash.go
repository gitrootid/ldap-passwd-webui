package util

import (
	"crypto/des"
	"encoding/hex"
	"strings"
)

func GenerateLMHashString(password string) string {
	hash := CreateLMHash(password)
	return hex.EncodeToString(hash)
}

// refer: https://github.com/newrelic/nri-mssql/blob/master/vendor/github.com/denisenkom/go-mssqldb/ntlm.go

func CreateLMHash(password string) (hash []byte) {
	var tmpHash [16]byte
	var lmpass [14]byte
	copy(lmpass[:14], []byte(strings.ToUpper(password)))
	magic := []byte("KGS!@#$%")
	encryptDes(lmpass[:7], magic, tmpHash[:8])
	encryptDes(lmpass[7:], magic, tmpHash[8:])
	hash = tmpHash[:]
	return
}

func encryptDes(key []byte, cleartext []byte, ciphertext []byte) {
	var desKey [8]byte
	createDesKey(key, desKey[:])
	cipher, err := des.NewCipher(desKey[:])
	if err != nil {
		panic(err)
	}
	cipher.Encrypt(ciphertext, cleartext)
}

func createDesKey(bytes, material []byte) {
	material[0] = bytes[0]
	material[1] = (byte)(bytes[0]<<7 | (bytes[1]&0xff)>>1)
	material[2] = (byte)(bytes[1]<<6 | (bytes[2]&0xff)>>2)
	material[3] = (byte)(bytes[2]<<5 | (bytes[3]&0xff)>>3)
	material[4] = (byte)(bytes[3]<<4 | (bytes[4]&0xff)>>4)
	material[5] = (byte)(bytes[4]<<3 | (bytes[5]&0xff)>>5)
	material[6] = (byte)(bytes[5]<<2 | (bytes[6]&0xff)>>6)
	material[7] = (byte)(bytes[6] << 1)
}
