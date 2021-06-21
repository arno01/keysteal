package keystore

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/ValleZ/javautf"
	"github.com/captainGeech42/keysteal/internal/lucene"
	"golang.org/x/crypto/pbkdf2"
)

type ElasticsearchKeystore struct {
	Path          string
	Version       int
	Contents      map[string]string // this type may need to change, it can have strings or files in it
	Password      string
	FormatVersion int32

	Salt []byte
	IV   []byte
}

var KEYSTORE_FILENAME = "elasticsearch.keystore"
var FORMAT_VERSION int32 = 4
var MIN_FORMAT_VERSION int32 = 1

func (k *ElasticsearchKeystore) DecryptKeystore() error {
	dataBytes, err := k.loadKeystore()
	if err != nil {
		return err
	}

	return k.decryptBytes(dataBytes)
}

// re-implementation ish of KeystoreWrapper#load() from https://github.com/elastic/elasticsearch
func (k *ElasticsearchKeystore) loadKeystore() ([]byte, error) {
	f, err := os.Open(k.Path)
	if err != nil {
		return nil, fmt.Errorf("open: %s", err)
	}
	defer f.Close()

	// check the version
	formatVersion, err := lucene.CheckHeader(f, KEYSTORE_FILENAME, MIN_FORMAT_VERSION, FORMAT_VERSION)
	if err != nil {
		return nil, fmt.Errorf("check header: %s", err)
	}

	k.FormatVersion = formatVersion

	// check if there is a password
	hasPasswordByte, err := lucene.ReadByte(f)
	if err != nil {
		return nil, fmt.Errorf("password byte: %s", err)
	}

	hasPassword := hasPasswordByte == 1
	if !hasPassword && hasPasswordByte != 0 {
		return nil, fmt.Errorf("corrupt keystore, invalid password byte: %#x", hasPasswordByte)
	}

	// check the encryption schemes for older versions
	if formatVersion <= 2 {
		typeStr, err := lucene.ReadString(f)
		if err != nil {
			return nil, fmt.Errorf("encryption type str: %s", err)
		}

		if typeStr != "PKCS12" {
			return nil, fmt.Errorf("corrupted legacy keystore string encryption type: %s", typeStr)
		}

		stringKeyAlgo, err := lucene.ReadString(f)
		if err != nil {
			return nil, fmt.Errorf("string key algo: %s", err)
		}

		if stringKeyAlgo != "PBE" {
			return nil, fmt.Errorf("corrupted legacy keystore string encryption algorithm: %s", typeStr)
		}

		if formatVersion == 2 {
			fileKeyAlgo, err := lucene.ReadString(f)
			if err != nil {
				return nil, fmt.Errorf("file key algo: %s", err)
			}

			if fileKeyAlgo != "PBE" {
				return nil, fmt.Errorf("corrupted legacy keystore file encryption algorithm: %s", typeStr)
			}
		}
	}

	var dataBytes []byte

	if formatVersion == 2 {
		// there is dumb java stuff happening here that is being serialized and i am lazy
		// TODO add support for version 2 keystores (low priority, i hope there aren't many of these itw)
		// https://github.com/elastic/elasticsearch/blob/master/server/src/main/java/org/elasticsearch/common/settings/KeyStoreWrapper.java#L247
		return nil, fmt.Errorf("version 2 keystores are not supported at this time")
	} else {
		dataBytesLen, err := readInt(f)
		if err != nil {
			return nil, fmt.Errorf("data bytes len: %s", err)
		}

		dataBytes = make([]byte, dataBytesLen)
		n, err := f.Read(dataBytes)
		if err != nil {
			return nil, fmt.Errorf("data bytes: %s", err)
		}
		if n != dataBytesLen {
			return nil, fmt.Errorf("didn't read enough bytes from file (%d instead of %d)", n, dataBytesLen)
		}
	}

	if err = lucene.CheckFooter(f); err != nil {
		return nil, fmt.Errorf("check footer: %s", err)
	}

	return dataBytes, nil
}

func (k *ElasticsearchKeystore) decryptBytes(dataBytes []byte) error {
	if k.FormatVersion <= 2 {
		return fmt.Errorf("no support for v1/2 keystores yet, open an issue (found version %d)", k.FormatVersion)
	}

	byteStream := bytes.NewReader(dataBytes)

	// read in the length of the salt
	saltLen, err := readInt(byteStream)
	if err != nil {
		return fmt.Errorf("salt length: %s", err)
	}

	// read in the salt
	k.Salt = make([]byte, saltLen)
	n, err := byteStream.Read(k.Salt)
	if n != saltLen {
		return fmt.Errorf("didn't get enough bytes for salt (%d instead of %d)", n, saltLen)
	}
	if err != nil {
		return fmt.Errorf("salt bytes: %s", err)
	}

	// read in the length of the IV
	ivLen, err := readInt(byteStream)
	if err != nil {
		return fmt.Errorf("iv length: %s", err)
	}

	// read in the IV
	k.IV = make([]byte, ivLen)
	n, err = byteStream.Read(k.IV)
	if n != ivLen {
		return fmt.Errorf("didn't get enough bytes for iv (%d instead of %d)", n, ivLen)
	}
	if err != nil {
		return fmt.Errorf("iv bytes: %s", err)
	}

	// read in the length of the encrypted data
	encBytesLen, err := readInt(byteStream)
	if err != nil {
		return fmt.Errorf("enc bytes length: %s", err)
	}

	// read in the encrypted data
	encBytes := make([]byte, encBytesLen)
	n, err = byteStream.Read(encBytes)
	if n != encBytesLen {
		return fmt.Errorf("didn't get enough bytes for enc data (%d instead of %d)", n, encBytesLen)
	}
	if err != nil {
		return fmt.Errorf("enc bytes: %s", err)
	}

	// generate the key
	key := pbkdf2.Key([]byte(k.Password), k.Salt, 10000, 16, sha512.New)

	// decrypt
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("new aes cipher: %s", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("new gcm: %s", err)
	}

	plaintext, err := gcm.Open(nil, k.IV, encBytes, k.Salt)
	if err != nil {
		return fmt.Errorf("gcm open: %s", err)
	}

	// successfully decrypted, populate the map
	plaintextSteam := bytes.NewReader(plaintext)
	numEntries, err := readInt(plaintextSteam)
	if err != nil {
		return fmt.Errorf("num entries: %s", err)
	}

	k.Contents = make(map[string]string)

	for i := 0; i < numEntries; i++ {
		// read the key
		key, err := javautf.ReadUTF(plaintextSteam)
		if err != nil {
			return fmt.Errorf("readutf keystore key: %s", err)
		}

		// get the type if v3
		if k.FormatVersion == 3 {
			// we don't need the value
			_, err := javautf.ReadUTF(plaintextSteam)
			if err != nil {
				return fmt.Errorf("setting type: %s", err)
			}
		}

		// get value length
		valueLen, err := readInt(plaintextSteam)
		if err != nil {
			return fmt.Errorf("value length: %s", err)
		}

		// get the value
		value := make([]byte, valueLen)
		n, err = plaintextSteam.Read(value)
		if n != valueLen {
			return fmt.Errorf("didn't get enough bytes for value (%d instead of %d)", n, valueLen)
		}
		if err != nil {
			return fmt.Errorf("value bytes: %s", err)
		}

		// store it in the map
		k.Contents[key] = string(value)
	}

	return nil
}

func (k *ElasticsearchKeystore) DefaultPaths() []string {
	return []string{"/etc/elasticsearch/elasticsearch.keystore"}
}

func (k *ElasticsearchKeystore) GetContents() map[string]string {
	return k.Contents
}

func (k *ElasticsearchKeystore) Name() string {
	return "Elasticsearch"
}

func (k *ElasticsearchKeystore) SetPath(path string) {
	k.Path = path
}

func (k *ElasticsearchKeystore) FindPassword() bool {
	return true
}

func (k *ElasticsearchKeystore) SetPassword(password string) {
	k.Password = password
}

func readInt(in io.Reader) (int, error) {
	byteArr := make([]byte, 4)

	n, err := in.Read(byteArr)
	if err != nil {
		return 0, err
	}

	if n != 4 {
		return 0, errors.New("didn't read enough bytes from file")
	}

	return int(binary.BigEndian.Uint32(byteArr)), nil
}
