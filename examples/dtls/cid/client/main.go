package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	piondtls "github.com/pion/dtls/v2"
	"github.com/plgd-dev/go-coap/v3/dtls"
)

func main() {
	co, err := dtls.Dial("localhost:5688", &piondtls.Config{
		PSK: func(hint []byte) ([]byte, error) {
			fmt.Printf("Server's hint: %s \n", hint)
			return []byte("hello"), nil
		},
		PSKIdentityHint:       []byte("Pion DTLS Client"),
		CipherSuites:          []piondtls.CipherSuiteID{piondtls.TLS_PSK_WITH_AES_128_CCM_8},
		ConnectionIDGenerator: piondtls.OnlySendCIDGenerator(),
	})
	if err != nil {
		log.Fatalf("Error dialing: %v", err)
	}
	path := "/a"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	resp, err := co.Get(ctx, path)
	if err != nil {
		log.Fatalf("Error sending request: %v", err)
	}
	log.Printf("Response payload: %+v", resp)
}
