package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/captainGeech42/keysteal/lib"
)

func init() {
	rootCmd.AddCommand(AllCmd)
}

var AllCmd = &cobra.Command{
	Use:   "all",
	Short: "Decrypts all keystores available",
	Run: func(cmd *cobra.Command, args []string) {
		keystores := []lib.Keystore{
			&lib.KibanaKeystore{},
		}

		for _, k := range keystores {
			// get path
			possiblePaths := append([]string{keystorePath}, k.DefaultPaths()...)
			path := lib.KeystoreExists(possiblePaths)
			if path == "" {
				fmt.Printf("failed to find %s keystore at these paths: %v\n", k.Name(), possiblePaths)
				return
			}

			fmt.Printf("found a %s keystore at %s\n", k.Name(), path)
			k.SetPath(path)

			// decrypt
			err := k.DecryptKeystore()
			if err != nil {
				panic(err)
			}

			// print the keystore
			fmt.Printf("=== %s keystore values ===\n", k.Name())
			lib.PrintKeystoreContents(k.GetContents())
		}
	},
}
