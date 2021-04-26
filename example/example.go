package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/KroneMultimedia/krn-auth-go/krn"
)

var (
	cryptKey   = os.Getenv("KRN_CRYPT_KEY")
	hmacSecret = os.Getenv("KRN_HMAC_SECRET")
	restKey    = os.Getenv("KRN_REST_KEY")
	rsaKey     = os.Getenv("KRN_RSA_KEY")
)

var pass = os.Args[1]

func main() {
	krnAuth := krn.NewKRNAuth("KRN", cryptKey, hmacSecret, restKey, rsaKey)
	payload, err := krnAuth.Validate(pass)
	if err != nil {
		fmt.Println(err)
		os.Exit(10)
	}

	b, err := json.MarshalIndent(payload, "", "  ")
	fmt.Printf("Token Valid!! Data \n %s\n", string(b))

	payload, err = krnAuth.DeepValidate(pass)
	if err != nil {
		fmt.Println(err)
		os.Exit(10)
	}

	b, err = json.MarshalIndent(payload, "", "  ")
	fmt.Printf("Token Valid!! Data \n %s\n", string(b))

}
