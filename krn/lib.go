package krn

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"time"

	"github.com/go-fed/httpsig"

	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	jwtgo "github.com/dgrijalva/jwt-go"
	"github.com/mergermarket/go-pkcs7"
)
// KRNAuth aa
type KRNAuth struct {
	Name       string
	CryptKey   string
	HMACSecret string
	RestKey    string
	RSAKey     string
}

var TRINITY_URL = "https://trinity.krone.at"

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

func (k *KRNAuth) SendRequest(method string, path string, headers map[string]string, body string) (string, error) {
	//create request
	url := fmt.Sprintf("%s%s", TRINITY_URL, path)
	hc := http.Client{}
	req, err := http.NewRequest(method, url, strings.NewReader(body))

	if err != nil {
		return "", err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Date", time.Now().UTC().String())
	req.Header.Set("krn-partner-key", k.RestKey)
	req.Header.Set("krn-sign-url", url)
	//sign request
	err = k.signRequest(req)
	if err != nil {
		return "", err
	}
	//send request
	resp, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	//return bytes
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	return string(bodyBytes), nil
}

type krnAuthRenewQuery struct {
	OperationName string            `json:"operationName"`
	Query         string            `json:"query"`
	Variables     map[string]string `json:"variables"`
}

func (k *KRNAuth) DeepValidate(inToken string) (string, error) {

	hc := http.Client{}

	url := fmt.Sprintf("%s/deep-validate?token=%s", TRINITY_URL, inToken)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return "", err

	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", err

	}
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(bodyBytes), nil
}

func (k *KRNAuth) Validate(inToken string) (interface{}, error) {
	tokenParts := strings.Split(inToken, ":")
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
	if err != nil {
		return nil, err
	}

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

func (k *KRNAuth) loadPrivateKey() (*rsa.PrivateKey, error) {

	pem, _ := pem.Decode([]byte(k.RSAKey))
	if pem == nil {
		return nil, errors.New("cannot decode pem")
	}
	if pem.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("RSA private key is of the wrong type: %s", pem.Type)
	}

	return x509.ParsePKCS1PrivateKey(pem.Bytes)
}

func (k *KRNAuth) signRequest(req *http.Request) error {

	/// Modifies R and adds signing headers
	headersToSign := []string{httpsig.RequestTarget, "krn-partner-key", "KRN-SIGN-URL", "Date"}
	signer, _, err := httpsig.NewSigner([]httpsig.Algorithm{httpsig.RSA_SHA256}, httpsig.DigestSha256, headersToSign, httpsig.Signature, 0)
	if err != nil {
		return err
	}
	privKey, err := k.loadPrivateKey()
	if err != nil {
		return err
	}
	if err := signer.SignRequest(privKey, "KRN", req, nil); err != nil {
		return err
	}

	return nil

}
