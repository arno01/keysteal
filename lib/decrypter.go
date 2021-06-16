package lib

import "fmt"

type Decrypter interface {
	DecryptKeystore() (map[string]string, error)
}

func PrintKeystoreContents(contents map[string]string) {
	for k, v := range contents {
		fmt.Printf("%s:\t%s\n", k, v)
	}
}
