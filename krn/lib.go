package krn

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
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

const TRINITY_URL = "https://lre-api.krone.at"

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

func (k *KRNAuth) sendRequest(method string, path string, headers []string, body string) []byte {
	//create request
	//sign request
	//send request
	//return bytes
	return []byte("a")
}

type krnAuthRenewQuery struct {
	OperationName string            `json:"operationName"`
	Query         string            `json:"query"`
	Variables     map[string]string `json:"variables"`
}

func (k *KRNAuth) DeepValidate(inToken string) (interface{}, error) {
	//FIXME MAKE GQL QUERY
	q := `
     mutation doRenew($passport: String!) {
                renew(passport: $passport) {
                    Message
                    Renewed
                    PassPort
                    Expires
                    Error
                    DecodedToken {
                        Email,
                        ID,
                        IntID,
                        NickName
                    }
                }
            } 
	`

	hc := http.Client{}
	form := url.Values{}
	que := krnAuthRenewQuery{
		OperationName: "doRenew",
		Query:         q,
		Variables:     map[string]string{"passport": inToken},
	}
	out, _ := json.Marshal(que)
	queryAsString := string(out)
	form.Add("operationName", "doRenew")
	form.Add("query", q)
	form.Add("variables", queryAsString)
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/graphql", TRINITY_URL), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err

	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err

	}

	fmt.Println(resp)
	return nil, nil
	/*

			$curl = curl_init(TRINITY_BASE_URL . '/graphql');
		        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
		        curl_setopt($curl, CURLOPT_POST, true);

		        curl_setopt($curl, CURLOPT_HTTPHEADER, array(
		            'Content-Type: application/json',
		        ));

		        curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode([
		            'operationName' => 'doRenew',
		            'query' => $RENEW_QUERY,
		            'variables' => [
		                'passport' => $token
		            ]
		        ]));
	*/
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
