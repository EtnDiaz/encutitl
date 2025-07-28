package main

import (
	"bufio"
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

const (
	keyFile = "key.bin"
	keySize = 32 // AES-256
)

var (
	fileFlag     = flag.String("f", "", "Input file path")
	stringFlag   = flag.String("s", "", "Input string")
	encrypt      = flag.Bool("e", false, "Encrypt mode")
	decrypt      = flag.Bool("d", false, "Decrypt mode")
	outputAsHex  = flag.Bool("output-as-hex", false, "Output in hex instead of base64")
	toStdout     = flag.Bool("to-stdout", false, "Write encrypted/decrypted data to stdout instead of file")
)

func main() {
	flag.Parse()

	// Handle Ctrl+C gracefully
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\nInterrupted.")
		os.Exit(1)
	}()

	if *encrypt == *decrypt {
		fmt.Println("Error: use exactly one of -e or -d")
		return
	}

	key, err := loadOrGenerateKey()
	if err != nil {
		fmt.Println("Key error:", err)
		return
	}

	var inputData []byte
	var inputName string

	if *fileFlag != "" {
		inputData, err = os.ReadFile(*fileFlag)
		inputName = *fileFlag
	} else if *stringFlag != "" {
		inputData = []byte(*stringFlag)
		inputName = "input"
	} else {
		fmt.Println("Error: provide input via -f <file> or -s <string>")
		return
	}
	if err != nil {
		fmt.Println("Input read error:", err)
		return
	}

	if *encrypt {
		result, err := compressEncrypt(key, inputData)
		if err != nil {
			fmt.Println("Encryption error:", err)
			return
		}
		if *toStdout {
			outputEncoded(result)
		} else {
			outFile := inputName + ".bin"
			err = os.WriteFile(outFile, result, 0600)
			if err != nil {
				fmt.Println("Write error:", err)
			} else {
				fmt.Println("Encrypted file saved to:", outFile)
			}
		}
	} else {
		var data []byte
		if *fileFlag != "" {
			data = inputData
		} else {
			if *outputAsHex {
				data, err = hex.DecodeString(strings.TrimSpace(string(inputData)))
			} else {
				data, err = base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(inputData)))
			}
			if err != nil {
				fmt.Println("Decode input error:", err)
				return
			}
		}

		plain, err := decryptDecompress(key, data)
		if err != nil {
			fmt.Println("Decryption error:", err)
			return
		}
		if *toStdout {
			fmt.Print(string(plain))
		} else {
			outFile := strings.TrimSuffix(inputName, ".bin") + ".dec"
			err := os.WriteFile(outFile, plain, 0600)
			if err != nil {
				fmt.Println("Write error:", err)
			} else {
				fmt.Println("Decrypted file saved to:", outFile)
			}
		}
	}
}

func compressEncrypt(key []byte, input []byte) ([]byte, error) {
	compressed := new(bytes.Buffer)
	writer, _ := flate.NewWriter(compressed, flate.BestCompression)
	_, err := writer.Write(input)
	if err != nil {
		return nil, err
	}
	writer.Close()

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	encrypted := gcm.Seal(nonce, nonce, compressed.Bytes(), nil)

	if *toStdout {
		return encrypted, nil
	}

	// default: return raw binary
	return encrypted, nil
}

func decryptDecompress(key []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]
	decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	r := flate.NewReader(bytes.NewReader(decrypted))
	defer r.Close()
	return io.ReadAll(r)
}

func loadOrGenerateKey() ([]byte, error) {
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		return generateKeyFile()
	}
	fmt.Print("Key exists. Use it? (y/n): ")
	reader := bufio.NewReader(os.Stdin)
	answer, _ := reader.ReadString('\n')
	if strings.TrimSpace(strings.ToLower(answer)) != "y" {
		return generateKeyFile()
	}
	return os.ReadFile(keyFile)
}

func generateKeyFile() ([]byte, error) {
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	err := os.WriteFile(keyFile, key, 0600)
	return key, err
}

func outputEncoded(data []byte) {
	if *outputAsHex {
		fmt.Println(hex.EncodeToString(data))
	} else {
		fmt.Println(base64.RawURLEncoding.EncodeToString(data))
	}
}

