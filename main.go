// Created by Nemesis
// Contact: nemesisuks@protonmail.com

package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/gen2brain/dlgs"
	"golang.org/x/crypto/argon2"
)

func HashFile(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha512.New()
	buf := make([]byte, 1048576) // 1MB buffer
	for {
		n, err := file.Read(buf)
		if n > 0 {
			if _, err := hash.Write(buf[:n]); err != nil {
				return "", err
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
	}

	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

// Generates a random salt of the specified size.
func GenerateSalt(size int) ([]byte, error) {
	salt := make([]byte, size)
	_, err := rand.Read(salt)
	return salt, err
}

// Derives an encryption key from password and salt using Argon2id
func GenerateKey(password []byte, salt []byte) []byte {
	// Used parameters: time=4, memory=64MB, threads=1, keyLen=32
	key := argon2.IDKey(password, salt, 4, 64*1024, 1, 32)
	return key
}

// Encrypts the data using AES-256-GCM and writes it to a file.
func EncryptAndWriteToFile(data []byte, filePath string, password []byte) error {
	salt, err := GenerateSalt(16) // Generate a random 16-byte salt
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(GenerateKey(password, salt))
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	ciphertextWithSalt := append(salt, ciphertext...)

	return os.WriteFile(filePath, ciphertextWithSalt, 0644)
}

// Decrypts the file using AES-256-GCM and loads the stored hashes.
func DecryptFileAndLoadHashes(filePath string, password []byte) (map[string]string, error) {
	ciphertextWithSalt, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	salt := ciphertextWithSalt[:16]
	ciphertext := ciphertextWithSalt[16:]

	block, err := aes.NewCipher(GenerateKey(password, salt))
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	storedHashes := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(string(plaintext)))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) == 2 {
			storedHashes[parts[0]] = parts[1]
		}
	}

	return storedHashes, scanner.Err()
}

// Recursively hashes all files in a directory and adds a progress bar.
func HashAllFilesInDirectory(rootDir string, verbose bool) (map[string]string, error) {
	hashes := make(map[string]string)

	// Gets the total number of files to process for the progress bar.
	totalFiles := 0
	filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			totalFiles++
		}
		return nil
	})

	fileCount := 0
	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			hash, err := HashFile(path)
			if err != nil {
				return err
			}
			relPath, err := filepath.Rel(rootDir, path)
			if err != nil {
				return err
			}

			// Replaces spaces with underscores in the relative path
			relPath = strings.ReplaceAll(relPath, " ", "_")

			hashes[relPath] = hash

			fileCount++
			if verbose {
				fmt.Printf("Hashed: %s\n", path)
			} else {
				printProgressBar(fileCount, totalFiles)
			}
		}
		return nil
	})

	if !verbose {
		fmt.Println() // Separates the progress bar from other output
	}

	return hashes, err
}

// Prints a text-based progress bar.
func printProgressBar(current, total int) {
	const progressBarWidth = 40
	progress := float64(current) / float64(total)
	barWidth := int(progress * progressBarWidth)

	fmt.Printf("\r[%s%s] %d/%d", strings.Repeat("=", barWidth), strings.Repeat(" ", progressBarWidth-barWidth), current, total)
}

func main() {

	// Defines command-line flags
	var (
		rootDir        = flag.String("dir", "", "The directory to hash and monitor for integrity")
		checkIntegrity = flag.Bool("check", false, "Check integrity of the selected directory")
		passwordFlag   = flag.String("password", "empty", "Encryption password for checksum storage")
		verbose        = flag.Bool("verbose", false, "Enable verbose output")
		interactive    = flag.Bool("interactive", false, "Enable interactive mode")
	)
	flag.Parse()

	if *interactive {
		// Uses the dlgs library to open a directory selection dialog
		selectedDir, _, err := dlgs.File("Select a directory", "", true)
		if err != nil {
			fmt.Printf("Error selecting directory: %v\n", err)
			return
		}
		*rootDir = selectedDir

		// Prompts the user for the password interactively
		fmt.Print("Enter the encryption password: ")

		password, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			fmt.Printf("Error reading password: %v\n", err)
			return
		}

		*passwordFlag = string(password)
	}

	password := []byte(*passwordFlag) // Uses the password provided

	// Gets the parent directory of the selected path
	parentDir := filepath.Dir(*rootDir)

	// Saves hashes.enc in the parent directory of the selected path
	hashFileName := fmt.Sprintf("%s.hashes.enc", filepath.Base(*rootDir))
	hashFilePath := filepath.Join(parentDir, hashFileName)

	if !*checkIntegrity {
		// Calculates and stores the hashes
		storedHashes, err := HashAllFilesInDirectory(*rootDir, *verbose)
		if err != nil {
			fmt.Printf("Error hashing files: %v\n", err)
			return
		}

		// Converts the hashes to a string
		var hashString strings.Builder
		for file, hash := range storedHashes {
			_, err := fmt.Fprintf(&hashString, "%s %s\n", file, hash)
			if err != nil {
				fmt.Printf("Error writing to the hash string: %v\n", err)
				return
			}
		}

		// Encrypts and stores the hashes in a file
		if err := EncryptAndWriteToFile([]byte(hashString.String()), hashFilePath, password); err != nil {
			fmt.Printf("Error encrypting and writing to the hash file: %v\n", err)
			return
		}

		fmt.Printf("Hashes stored in %s\n", hashFilePath)
	} else {
		// Checks the integrity
		// Decrypts the file and loads stored hashes
		storedHashes, err := DecryptFileAndLoadHashes(hashFilePath, password)
		if err != nil {
			fmt.Printf("Error decrypting and loading stored hashes: %v\n", err)
			return
		}

		recalculatedHashes, err := HashAllFilesInDirectory(*rootDir, *verbose)
		if err != nil {
			fmt.Printf("Error recalculating hashes: %v\n", err)
			return
		}

		integrityFailed := false

		// Identifies new and modified files
		for file, recalculatedHash := range recalculatedHashes {
			storedHash, ok := storedHashes[file]
			if !ok || storedHash != recalculatedHash {
				// Checks if the file path contains underscores that were replaced earlier
				if strings.Contains(file, "_") {
					// Replaces underscores with spaces in the file path
					originalFilePath := strings.ReplaceAll(file, "_", " ")
					if !ok {
						fmt.Printf("New file detected: %s\n", originalFilePath)
					} else {
						fmt.Printf("Integrity check failed for: %s\n", originalFilePath)
					}
				} else {
					if !ok {
						fmt.Printf("New file detected: %s\n", file)
					} else {
						fmt.Printf("Integrity check failed for: %s\n", file)
					}
				}
				integrityFailed = true
			}
		}

		// Identifies deleted files
		for file := range storedHashes {
			_, ok := recalculatedHashes[file]
			if !ok {
				// Checks if the file path contains underscores that were replaced earlier
				if strings.Contains(file, "_") {
					// Replaces underscores with spaces in the file path
					originalFilePath := strings.ReplaceAll(file, "_", " ")
					fmt.Printf("Deleted file detected: %s\n", originalFilePath)
				} else {
					fmt.Printf("Deleted file detected: %s\n", file)
				}
				integrityFailed = true
			}
		}

		if !integrityFailed {
			fmt.Println("Integrity check successful. All files are verified. ✔️")
		} else {
			fmt.Println("Some files are missing or have been modified. ❌")
		}
	}
}
