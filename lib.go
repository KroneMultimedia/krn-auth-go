package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	jwtgo "github.com/dgrijalva/jwt-go"
	"github.com/mergermarket/go-pkcs7"
)

type KRNAuth struct {
	Name       string
	CryptKey   string
	HMACSecret string
	RestKey    string
	RSAKey     string
}

func NewKRNAuth(name string, crypt_key string, hmac_secret string, rest_key string, rsa_key string) KRNAuth {
	n := KRNAuth{
		Name:       name,
		CryptKey:   crypt_key,
		HMACSecret: hmac_secret,
		RestKey:    rest_key,
		RSAKey:     rsa_key,
	}
	return n
}

func (k *KRNAuth) Validate(token string) (interface{}, error) {
	tokenParts := strings.Split(token, ":")
	if tokenParts[0] != k.Name {
		return nil, errors.New("Invalid token")
	}

	token, err := jwtgo.Parse(tokenParts[1], func(token *jwtgo.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwtgo.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(k.HMACSecret), nil
	})

	if claims, ok := token.Claims.(jwtgo.MapClaims); ok && token.Valid {
		var decoded map[string]interface{}
		ipayload, _ := k.decryptString(fmt.Sprintf("%s", claims["payload"]))
		_ = json.Unmarshal([]byte(ipayload), &decoded)
		return decoded, nil
	} else {
		return nil, err
	}

	return nil, nil
}

/// INTERNAL do not use
// decryptString Decrypt decrypts cipher text string into plain text string
func (k *KRNAuth) decryptString(encrypted string) (string, error) {

	//b64 decode
	cipherText, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}

	key := []byte(k.CryptKey)
	//cipherText, _ := hex.DecodeString(encrypted)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	if len(cipherText) < aes.BlockSize {
		panic("cipherText too short")
	}
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]
	if len(cipherText)%aes.BlockSize != 0 {
		panic("cipherText is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(cipherText, cipherText)

	cipherText, _ = pkcs7.Unpad(cipherText, aes.BlockSize)
	return fmt.Sprintf("%s", cipherText), nil
}
