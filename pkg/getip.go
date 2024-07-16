package pkg

import (
	"fmt"
	"io"
	"net"
	"net/http"
)

func GetIPUsingDialer(dial func(network, addr string) (net.Conn, error)) (string, error) {
	client := http.Client{
		Transport: &http.Transport{
			Dial: dial,
		},
	}

	resp, err := client.Get("http://ifconfig.me/")
	if err != nil {
		return "", fmt.Errorf("failed to perform HTTP request: %v", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}

	return string(body), nil
}
