package keystore

import (
	"fmt"
	"os"

	"github.com/captainGeech42/keysteal/internal/lucene"
)

type ElasticsearchKeystore struct {
	Path     string
	Version  int
	Contents map[string]string // this type may need to change, it can have strings or files in it
	Password string
}

var KEYSTORE_FILENAME = "elasticsearch.keystore"
var FORMAT_VERSION = 4
var MIN_FORMAT_VERSION = 1

func (k *ElasticsearchKeystore) DecryptKeystore() error {
	f, err := os.Open(k.Path)
	if err != nil {
		return err
	}
	defer f.Close()

	// check the version
	formatVersion, err := lucene.CheckHeader(f, KEYSTORE_FILENAME, MIN_FORMAT_VERSION, FORMAT_VERSION)
	if err != nil {
		return err
	}

	// check if there is a password
	hasPasswordByte, err := lucene.ReadByte(f)
	if err != nil {
		return err
	}
	hasPassword := hasPasswordByte == 1
	fmt.Printf("%x\n", hasPasswordByte)
	fmt.Println(hasPassword)
	fmt.Println(formatVersion)

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
