package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"syscall"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"
)

// decrypt Metamask vault
//muquit@muquit.com - January-24-2022 18:16:38

type MetamaskVault struct {
	Data string `json:"data"`
	Iv string `json:"iv"`
	Salt string `json:"salt"`
}

func genKeyFromPassword(password []byte, salt []byte) (key []byte) {
	iter := 10000
	keyLen := 32

	hash := pbkdf2.Key(password, salt, iter, keyLen, sha256.New)
	return hash
}

func main() {
	// -f
	var filePath string
	flag.StringVar(&filePath, "f", "", "Path of Metamask vault JSON file")
	flag.Parse()
	if len(filePath) == 0 {
		flag.Usage()
		os.Exit(0)
	}

	// open the vault JSON file
	jf, err := os.Open(filePath)
	if err != nil {
		log.Fatal(err)
	}
	defer jf.Close()

	// read JSON to bytes
	jBytes, err := ioutil.ReadAll(jf)
	if err != nil {
		log.Fatal(err)
	}

	var vault MetamaskVault
	json.Unmarshal(jBytes, &vault)


	saltBytes, err := base64.StdEncoding.DecodeString(vault.Salt)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Print("Enter Metamask Password: ")
	metaMaskPasswordBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println()

	// generate key from password
	key := genKeyFromPassword(metaMaskPasswordBytes, saltBytes)
//	fmt.Println(hex.EncodeToString(key))

	// decrypt data with the key. AES-256 GCM mode
	ivBytes, err := base64.StdEncoding.DecodeString(vault.Iv)
	if err != nil {
		log.Fatal(err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}
	aesgcm, err := cipher.NewGCMWithNonceSize(block, len(ivBytes))
	if err != nil {
		log.Fatal(err)
	}
	cipherTextBytes, err := base64.StdEncoding.DecodeString(vault.Data)
	if err != nil {
		log.Fatal(err)
	}

	plainTextBytes, err := aesgcm.Open(nil, ivBytes, cipherTextBytes, nil)
	if err != nil {
		log.Fatal(err)
	}
	plainText := string(plainTextBytes)
	fmt.Println(plainText)
}