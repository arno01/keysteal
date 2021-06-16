package lib

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

type KibanaKeystore struct {
	Path     string
	Version  int
	Contents map[string]string
	Password string

	Salt []byte
	IV   []byte
	Tag  []byte
	Key  []byte
}

func (k *KibanaKeystore) DecryptKeystore() error {
	f, err := os.Open(k.Path)
	if err != nil {
		return err
	}

	keystoreBytes, err := ioutil.ReadAll(f)
	if err != nil {
		return err
	}

	// parse out the version number
	splitSlice := strings.Split(string(keystoreBytes), ":")
	if len(splitSlice) != 2 {
		return errors.New("invalid keystore format")
	}

	versionNumber, err := strconv.Atoi(splitSlice[0])
	if err != nil {
		return err
	}

	// there is only one kibana keystore version as nof now
	if versionNumber != 1 {
		return fmt.Errorf("invalid version number in keystore: %d", versionNumber)
	}

	// base64 decode the buffer
	keystoreDataBytes, err := base64.StdEncoding.DecodeString(splitSlice[1])
	if err != nil {
		return err
	}

	// set values
	k.Salt = keystoreDataBytes[:64]
	k.IV = keystoreDataBytes[64:76]
	k.Tag = keystoreDataBytes[76:92]
	text := keystoreDataBytes[92:]

	// generate the key
	key := pbkdf2.Key([]byte(k.Password), k.Salt, 10000, 32, sha512.New)

	// decrypt
	// https://gist.github.com/kkirsche/e28da6754c39d5e7ea10
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	plaintext, err := gcm.Open(nil, k.IV, append(text, k.Tag...), nil)
	if err != nil {
		return err
	}

	fmt.Println(string(plaintext))
	return nil
}