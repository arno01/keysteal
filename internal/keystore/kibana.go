package keystore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
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

	err = json.Unmarshal(plaintext, &k.Contents)
	if err != nil {
		return err
	}

	return nil
}

func (k *KibanaKeystore) DefaultPaths() []string {
	return []string{"/etc/kibana/kibana.keystore"}
}

func (k *KibanaKeystore) GetContents() map[string]string {
	return k.Contents
}

func (k *KibanaKeystore) Name() string {
	return "Kibana"
}

func (k *KibanaKeystore) SetPath(path string) {
	k.Path = path
}

func (k *KibanaKeystore) FindPassword() bool {
	// even though the keystore code in Kibana supports passwords,
	// it was never implemented in the rest of Kibana (as of 7.13)

	return true
}

func (k *KibanaKeystore) SetPassword(password string) {
	k.Password = password
}
