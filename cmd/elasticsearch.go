package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/captainGeech42/keysteal/internal/keystore"
)

func init() {
	ElasticsearchCmd.Flags().StringVarP(&keystorePath, "path", "p", "", "Path to the Elasticsearch keystore")
	rootCmd.AddCommand(ElasticsearchCmd)
}

var ElasticsearchCmd = &cobra.Command{
	Use:   "elasticsearch",
	Short: "Decrypts the Elasticsearch keystore",
	Run: func(cmd *cobra.Command, args []string) {
		k := &keystore.ElasticsearchKeystore{}

		// get path
		possiblePaths := append([]string{keystorePath}, k.DefaultPaths()...)
		path := keystore.KeystoreExists(possiblePaths)
		if path == "" {
			fmt.Printf("failed to find Elasticsearch keystore at these paths: %v\n", possiblePaths)
			return
		}

		fmt.Printf("found a keystore at %s\n", path)
		k.Path = path

		// decrypt
		err := k.DecryptKeystore()
		if err != nil {
			panic(err)
		}

		// print the keystore
		fmt.Println("=== Elasticsearch keystore values ===")
		keystore.PrintKeystoreContents(k.GetContents())
	},
}
