package cmd

import (
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(ElasticsearchCmd)
}

var ElasticsearchCmd = &cobra.Command{
	Use:   "elasticsearch",
	Short: "Decrypts the Elasticsearch keystore",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Println("hello from elasticsearch Run()")
	},
}
