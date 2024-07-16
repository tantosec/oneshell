package pkg

import (
	"log"
	"os"
	"path/filepath"

	"github.com/kevinburke/ssh_config"
	"github.com/mitchellh/go-homedir"
	"golang.org/x/crypto/ssh"
)

var knownIdentityFiles []string = []string{"id_rsa", "id_ecdsa", "id_ecdsa_sk", "id_ed25519", "id_ed25519_sk", "id_dsa"}

func ConnectToSSHHost(host string) *ssh.Client {
	homeDir, err := homedir.Dir()
	if err != nil {
		log.Fatalf("failed to get user home directory: %v", err)
	}

	sshConfigPath := filepath.Join(homeDir, ".ssh", "config")
	configFile, err := os.Open(sshConfigPath)
	if err != nil {
		log.Fatalf("failed to open .ssh/config file: %v", err)
	}
	defer configFile.Close()

	config, err := ssh_config.Decode(configFile)
	if err != nil {
		log.Fatalf("failed to decode .ssh/config file: %v", err)
	}

	found := false
	for _, currHost := range config.Hosts {
		if currHost.Matches(host) {
			found = true
		}
	}
	if !found {
		log.Fatalf("could not find ssh config entry '%v'", host)
	}

	user, err := config.Get(host, "User")
	if err != nil {
		log.Fatalf("failed to retrieve user value from config file: %v", err)
	}

	if user == "" {
		user := os.Getenv("USER")
		if user == "" {
			log.Fatalf("failed to get user for ssh connection: %v", err)
		}

		log.Printf("User not specified in ssh config, using %v\n", user)
	}

	hostname, err := config.Get(host, "HostName")
	if err != nil {
		log.Fatalf("error occurred when retrieving HostName from ssh config: %v", err)
	}
	if hostname == "" {
		hostname = host

		log.Printf("Hostname not specified in ssh config, using %v\n", hostname)
	}

	port, err := config.Get(host, "Port")
	if err != nil {
		log.Fatalf("error occurred when retrieving Port from ssh config: %v", err)
	}
	if port == "" {
		port = "22"

		log.Printf("Port not specified in ssh config, using %v\n", port)
	}

	identityFile, err := config.Get(host, "IdentityFile")
	if err != nil {
		log.Fatalf("error occurred when retrieving IdentityFile from ssh config: %v", err)
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
			log.Fatalf("could not find identity file for ssh host %v", host)
		} else {
			log.Printf("IdentityFile not specified in ssh config, using %v\n", identityFile)
		}
	} else {
		identityFile, err = homedir.Expand(identityFile)
		if err != nil {
			log.Fatalf("failed to parse pathname for identityFile: %v", err)
		}
	}

	privKey, err := os.ReadFile(identityFile)
	if err != nil {
		log.Fatalf("failed to read private key: %v", err)
	}

	signer, err := ssh.ParsePrivateKey(privKey)
	if err != nil {
		log.Fatalf("failed to parse private key: %v", err)
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
		log.Fatalf("failed to connect to SSH server: %v", err)
	}

	return client
}
