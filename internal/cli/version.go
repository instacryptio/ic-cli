package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	// Set via ldflags at build time
	Version   = "dev"
	CommitSHA = "none"
	BuildDate = "unknown"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version and build info",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("icc %s (%s) built %s\n", Version, CommitSHA, BuildDate)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
