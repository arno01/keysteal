package cmd

import (
	"github.com/spf13/cobra"

	"github.com/captainGeech42/keysteal/lib"
)

var keystorePath string

func init() {
	KibanaCmd.Flags().StringVarP(&keystorePath, "path", "p", "/etc/kibana/kibana.keystore", "Path to the Kibana keystore")
	rootCmd.AddCommand(KibanaCmd)
}

var KibanaCmd = &cobra.Command{
	Use:   "kibana",
	Short: "Decrypts the kibana keystore",
	Run: func(cmd *cobra.Command, args []string) {
		k := &lib.KibanaKeystore{
			Path: keystorePath,
		}

		err := k.DecryptKeystore()
		if err != nil {
			panic(err)
		}
	},
}
