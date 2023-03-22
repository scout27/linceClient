package linceClient

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/goccy/go-json"
	"io"
	"net/http"
	"strconv"
)

func CheckLicense(product string, license string, buildId string, key string) bool {
	res, err := http.Get("https://license-guard.me/api/check_key/" + product + "?license=" + license + "&buildId=" + buildId)
	if err != nil {
		fmt.Println("Error. Can't connect to server. Please check your internet connection.")
		return false
	}
	defer res.Body.Close()
	if res.StatusCode == 200 {
		var answer Answer
		body, err := io.ReadAll(res.Body)
		if err != nil {
			fmt.Println("Error. Can't read response from server. Try restart software.")
			return false
		}
		err = json.Unmarshal(body, &answer)
		if err != nil {
			fmt.Println("Error. Can't read response from server. Try restart software.")
			return false
		}

		keyBytes, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			fmt.Println("Error. Can't read response from server. Try restart software.")
			return false
		}
		PublicKey, err := x509.ParsePKCS1PublicKey(keyBytes)
		if err != nil {
			fmt.Println("Error. Can't read response from server. Try restart software.")
			return false
		}
		hashed := sha256.Sum256([]byte(answer.Status))
		signatureBytes, err := hex.DecodeString(answer.Signature)
		if err != nil {
			fmt.Println("Error. Can't read response from server. Try restart software.")
			return false
		}
		err = rsa.VerifyPSS(PublicKey, crypto.SHA256, hashed[:], signatureBytes, nil)
		if err != nil {
			fmt.Println("Error. Strange behavior is detected. Your license will be revoked in 3 days unless you contact @manager_biznes_sharks")
			return false
		}
		status := unchipr(&answer.Status)
		return status%32 == 0
	}
	return false
}

func chipr(a *uint64) string {
	x := strconv.FormatUint(*a, 10)
	for i := range x {
		switch x[i] {
		case '0':
			x = x[:i] + "9" + x[i+1:]
		case '1':
			x = x[:i] + "8" + x[i+1:]
		case '2':
			x = x[:i] + "7" + x[i+1:]
		case '3':
			x = x[:i] + "6" + x[i+1:]
		case '4':
			x = x[:i] + "5" + x[i+1:]
		case '5':
			x = x[:i] + "4" + x[i+1:]
		case '6':
			x = x[:i] + "3" + x[i+1:]
		case '7':
			x = x[:i] + "2" + x[i+1:]
		case '8':
			x = x[:i] + "1" + x[i+1:]
		case '9':
			x = x[:i] + "0" + x[i+1:]
		}
	}
	return x
}

func unchipr(a *string) uint64 {
	x := *a
	for i := range x {
		switch x[i] {
		case '0':
			x = x[:i] + "9" + x[i+1:]
		case '1':
			x = x[:i] + "8" + x[i+1:]
		case '2':
			x = x[:i] + "7" + x[i+1:]
		case '3':
			x = x[:i] + "6" + x[i+1:]
		case '4':
			x = x[:i] + "5" + x[i+1:]
		case '5':
			x = x[:i] + "4" + x[i+1:]
		case '6':
			x = x[:i] + "3" + x[i+1:]
		case '7':
			x = x[:i] + "2" + x[i+1:]
		case '8':
			x = x[:i] + "1" + x[i+1:]
		case '9':
			x = x[:i] + "0" + x[i+1:]
		}
	}
	res, _ := strconv.ParseUint(x, 10, 64)
	return res
}
