// Package control implements control-plane message formats. Legacy
// payload encoding is used only inside certificate-verified HTTPS connections.
package control

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"io"
)

// Recovered from libtxcore TxAES::Encode and libNetCorePlugin HttpRequest.
// These public protocol constants provide encoding compatibility, not identity.
var legacyKey = []byte("3U7f4yBM4&LiJp9d")
var legacyIV = []byte("jzThmvU0yO*&^8GW")

func EncodeLegacy(body []byte) ([]byte, error) {
	var compressed bytes.Buffer
	w, err := zlib.NewWriterLevel(&compressed, 9)
	if err != nil {
		return nil, err
	}
	if _, err = w.Write(body); err != nil {
		return nil, err
	}
	if err = w.Close(); err != nil {
		return nil, err
	}
	padded := compressed.Bytes()
	padding := aes.BlockSize - len(padded)%aes.BlockSize
	padded = append(padded, bytes.Repeat([]byte{byte(padding)}, padding)...)
	block, err := aes.NewCipher(legacyKey)
	if err != nil {
		return nil, err
	}
	encrypted := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, legacyIV).CryptBlocks(encrypted, padded)
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(encrypted)))
	base64.StdEncoding.Encode(encoded, encrypted)
	return encoded, nil
}

func DecodeLegacy(encoded []byte) ([]byte, error) {
	if len(encoded) > 2<<20 {
		return nil, errors.New("encoded control response too large")
	}
	encrypted, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(encoded)))
	if err != nil || len(encrypted) == 0 || len(encrypted)%aes.BlockSize != 0 {
		return nil, errors.New("invalid encoded control response")
	}
	block, err := aes.NewCipher(legacyKey)
	if err != nil {
		return nil, err
	}
	padded := make([]byte, len(encrypted))
	cipher.NewCBCDecrypter(block, legacyIV).CryptBlocks(padded, encrypted)
	n := int(padded[len(padded)-1])
	if n < 1 || n > aes.BlockSize || n > len(padded) {
		return nil, errors.New("invalid control response padding")
	}
	for _, b := range padded[len(padded)-n:] {
		if int(b) != n {
			return nil, errors.New("invalid control response padding")
		}
	}
	r, err := zlib.NewReader(bytes.NewReader(padded[:len(padded)-n]))
	if err != nil {
		return nil, errors.New("invalid compressed control response")
	}
	defer r.Close()
	result, err := io.ReadAll(io.LimitReader(r, (1<<20)+1))
	if err != nil || len(result) > 1<<20 {
		return nil, errors.New("invalid or oversized decoded control response")
	}
	return result, nil
}
