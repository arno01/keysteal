package keystore

import (
	"fmt"
	"os"
)

type Keystore interface {
	// once the path for a keystore is set, call DecryptKeystore() to decrypt
	// the keystore. if the password is invalid, it will error out.
	DecryptKeystore() error

	// returns a slice of paths where the keystore could be found
	DefaultPaths() []string

	// returns a key-value mapping of the keystore contents
	GetContents() map[string]string

	// returns the product name associated with the keystore (e.g. Kibana)
	Name() string

	// sets the path for the specific keystore after having found a valid one
	SetPath(string)

	// checks env vars, config files, etc. for a possible keystore file password.
	// returns true if it finds a password, false if not. this function should
	// not be called if a password was provided by the user.
	FindPassword() bool

	// set password, can be used if password is passed as an argument or from stdin.
	// this should only be called when running a single keystore.
	SetPassword(string)
}

func PrintKeystoreContents(contents map[string]string) {
	for k, v := range contents {
		fmt.Printf("%s:\t%s\n", k, v)
	}
}

func KeystoreExists(paths []string) string {
	for _, p := range paths {
		// check if file exists
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	return ""
}
