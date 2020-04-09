package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/csv"
	"fmt"
	"io/ioutil"
	"log"
	"os/user"
	"path"
	"syscall"

	"github.com/pcarrier/gauth/gauth"
	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	user, e := user.Current()
	if e != nil {
		log.Fatal(e)
	}
	cfgPath := path.Join(user.HomeDir, ".config/gauth.csv")

	cfgContent, e := ioutil.ReadFile(cfgPath)
	if e != nil {
		log.Fatal(e)
	}

	// Support for 'openssl enc -aes-128-cbc -md sha256 -pass pass:'
	if bytes.HasPrefix(cfgContent, []byte("Salted__")) {
		fmt.Printf("Encryption password: ")
		passwd, e := terminal.ReadPassword(int(syscall.Stdin))
		fmt.Printf("\n")
		if e != nil {
			log.Fatal(e)
		}
		salt := cfgContent[8:16]
		rest := cfgContent[16:]
		salting := sha256.New()
		salting.Write([]byte(passwd))
		salting.Write(salt)
		sum := salting.Sum(nil)
		key := sum[:16]
		iv := sum[16:]
		block, e := aes.NewCipher(key)
		if e != nil {
			log.Fatal(e)
		}

		mode := cipher.NewCBCDecrypter(block, iv)
		mode.CryptBlocks(rest, rest)
		// Remove padding
		i := len(rest) - 1
		for rest[i] < 16 {
			i--
		}
		cfgContent = rest[:i]
	}

	cfgReader := csv.NewReader(bytes.NewReader(cfgContent))
	// Unix-style tabular
	cfgReader.Comma = ':'

	cfg, e := cfgReader.ReadAll()
	if e != nil {
		log.Fatal(e)
	}

	currentTS, _ := gauth.IndexNow()

	for _, record := range cfg {
		_, secret := record[0], record[1]
		_, curr, _, err := gauth.Codes(secret, currentTS)
		if err != nil {
			log.Fatalf("Code: %v", err)
		}
		fmt.Println(curr)
	}

}
