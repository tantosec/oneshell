package pkg

import (
	"github.com/pion/stun"
)

// Based off https://github.com/Snawoot/extip/blob/master/extip.go
func QueryStunServerForIp(server string) (string, error) {
	family := "udp4"
	c, err := stun.Dial(family, server)
	if err != nil {
		return "", err
	}
	defer c.Close()

	message, err := stun.Build(stun.TransactionID, stun.BindingRequest)
	if err != nil {
		return "", err
	}

	clientOut := make(chan stun.Event)
	clientErr := make(chan error)

	go func() {
		err := c.Do(message, func(res stun.Event) {
			clientOut <- res
		})
		if err != nil {
			clientErr <- err
		}
	}()

	select {
	case err := <-clientErr:
		return "", err
	case res := <-clientOut:
		if res.Error != nil {
			return "", res.Error
		}
		var xorAddr stun.XORMappedAddress
		if err := xorAddr.GetFrom(res.Message); err == nil {
			return xorAddr.IP.String(), nil
		} else {
			var mappedAddr stun.MappedAddress
			if err := mappedAddr.GetFrom(res.Message); err == nil {
				return mappedAddr.IP.String(), nil
			} else {
				return "", err
			}
		}
	}
}

func GetMyIP() (string, error) {
	return QueryStunServerForIp("stun.l.google.com:19302")
}
