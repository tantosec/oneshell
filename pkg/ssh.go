package pkg

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"

	"github.com/kevinburke/ssh_config"
	"github.com/mitchellh/go-homedir"
	"golang.org/x/crypto/ssh"
)

var knownIdentityFiles []string = []string{"id_rsa", "id_ecdsa", "id_ecdsa_sk", "id_ed25519", "id_ed25519_sk", "id_dsa"}

func ConnectToSSHHost(host string, listenAddress string, testPort uint16, bypassSanityCheck bool) (*ssh.Client, error) {
	homeDir, err := homedir.Dir()
	if err != nil {
		return nil, fmt.Errorf("failed to get user home directory: %v", err)
	}

	sshConfigPath := filepath.Join(homeDir, ".ssh", "config")
	configFile, err := os.Open(sshConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open .ssh/config file: %v", err)
	}
	defer configFile.Close()

	config, err := ssh_config.Decode(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to decode .ssh/config file: %v", err)
	}

	found := false
	for _, currHost := range config.Hosts {
		if currHost.Matches(host) {
			found = true
		}
	}
	if !found {
		return nil, fmt.Errorf("could not find ssh config entry '%v'", host)
	}

	user, err := config.Get(host, "User")
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve user value from config file: %v", err)
	}

	if user == "" {
		user := os.Getenv("USER")
		if user == "" {
			return nil, fmt.Errorf("failed to get user for ssh connection: %v", err)
		}

		log.Printf("User not specified in ssh config, using %v\n", user)
	}

	hostname, err := config.Get(host, "HostName")
	if err != nil {
		return nil, fmt.Errorf("error occurred when retrieving HostName from ssh config: %v", err)
	}
	if hostname == "" {
		hostname = host

		log.Printf("Hostname not specified in ssh config, using %v\n", hostname)
	}

	port, err := config.Get(host, "Port")
	if err != nil {
		return nil, fmt.Errorf("error occurred when retrieving Port from ssh config: %v", err)
	}
	if port == "" {
		port = "22"

		log.Printf("Port not specified in ssh config, using %v\n", port)
	}

	identityFile, err := config.Get(host, "IdentityFile")
	if err != nil {
		return nil, fmt.Errorf("error occurred when retrieving IdentityFile from ssh config: %v", err)
	}
	if identityFile == "" {
		for _, kif := range knownIdentityFiles {
			kifPath := filepath.Join(homeDir, ".ssh", kif)
			if _, err := os.Stat(kifPath); err == nil {
				identityFile = kifPath
				break
			}
		}

		if identityFile == "" {
			return nil, fmt.Errorf("could not find identity file for ssh host %v", host)
		} else {
			log.Printf("IdentityFile not specified in ssh config, using %v\n", identityFile)
		}
	} else {
		identityFile, err = homedir.Expand(identityFile)
		if err != nil {
			return nil, fmt.Errorf("failed to parse pathname for identityFile: %v", err)
		}
	}

	privKey, err := os.ReadFile(identityFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %v", err)
	}

	signer, err := ssh.ParsePrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	sshConfig := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", hostname+":"+port, sshConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SSH server: %v", err)
	}

	if !bypassSanityCheck {
		err = testListenAllInterfaces(client, hostname, listenAddress, testPort)
		if err != nil {
			return nil, err
		}
	}

	return client, nil
}

func testListenAllInterfaces(client *ssh.Client, hostname string, listenAddress string, testPort uint16) error {
	log.Println("Testing connection to SSH server to ensure SSH port forward works...")

	l, err := client.Listen("tcp", fmt.Sprintf("%v:%v", listenAddress, testPort))
	if err != nil {
		return fmt.Errorf("failed to start test listener: %v", err)
	}

	defer l.Close()

	go func() {
		c, err := l.Accept()
		if err == nil {
			c.Close()
		}
	}()

	c, err := net.Dial("tcp", fmt.Sprintf("%v:%v", hostname, testPort))
	if err != nil {
		fmt.Println()
		fmt.Println("During a test connection to the SSH instance, it was found that the desired port was unreachable. This could mean that sshd does not allow listening on all interfaces. To fix this, add the following line to /etc/ssh/sshd_config on the remote:")
		fmt.Println()
		fmt.Println("GatewayPorts clientspecified")
		fmt.Println()
		fmt.Println("This allows oneshell to listen on public interfaces on the remote machine.")
		fmt.Println("If you know what you're doing and want to continue anyway, bypass this sanity check with --bypass-ssh-sanity-check")
		fmt.Println()

		return fmt.Errorf("failed to connect to ssh server: %v", err)
	}

	err = c.Close()
	if err != nil {
		return fmt.Errorf("error closing temporary connection: %v", err)
	}

	return nil
}
