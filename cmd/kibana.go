package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/captainGeech42/keysteal/lib"
)

var keystorePath string

func init() {
	KibanaCmd.Flags().StringVarP(&keystorePath, "path", "p", "", "Path to the Kibana keystore")
	rootCmd.AddCommand(KibanaCmd)
}

var KibanaCmd = &cobra.Command{
	Use:   "kibana",
	Short: "Decrypts the kibana keystore",
	Run: func(cmd *cobra.Command, args []string) {
		k := &lib.KibanaKeystore{}

		// get path
		possiblePaths := append([]string{keystorePath}, k.DefaultPaths()...)
		path := lib.KeystoreExists(possiblePaths)
		if path == "" {
			fmt.Printf("failed to find Kibana keystore at these paths: %v\n", possiblePaths)
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
		fmt.Println("=== Kibana keystore values ===")
		lib.PrintKeystoreContents(k.GetContents())
	},
}
