package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "keysteal",
	Short: "Decrypt secrets in Elastic keystores",
	Long: `Decrypt secrets from Elasticsearch, Kibana, Logstash, and Beats keystores, which can provide sensitive information.

Source available at https://github.com/captainGeech42/keysteal`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Println("hello from root Run()")
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
