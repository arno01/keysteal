package keystore

import (
	"encoding/binary"
	"errors"
	"os"
)

type ElasticsearchKeystore struct {
	Path     string
	Version  int
	Contents map[string]string // this type may need to change, it can have strings or files in it
	Password string
}

var CODEC_MAGIC uint32 = 0x3fd76c17
var FOOTER_MAGIC uint32 = ^CODEC_MAGIC

func (k *ElasticsearchKeystore) DecryptKeystore() error {
	f, err := os.Open(k.Path)
	if err != nil {
		return err
	}

	// check the version
	codecHeader := make([]byte, 4)
	_, err = f.Read(codecHeader)

	codecHeaderInt := binary.BigEndian.Uint32(codecHeader)
	if codecHeaderInt != CODEC_MAGIC {
		return errors.New("invalid magic bytes in codec header, is this a valid Elasticsearch keystore?")
	}

	return nil
}
