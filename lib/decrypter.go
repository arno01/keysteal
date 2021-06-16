package lib

type Decrypter interface {
	DecryptKeystore() error
}
