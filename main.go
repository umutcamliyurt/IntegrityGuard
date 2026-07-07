package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unsafe"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

const fileVersion byte = 2

const flagYubikey byte = 1 << 0

const yubikeyChallengeSize = 64

const minPasswordLength = 12

const sha512HexLen = 128

func HashFile(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha512.New()
	buf := make([]byte, 1024*1024)

	for {
		n, err := file.Read(buf)
		if n > 0 {
			if _, werr := hash.Write(buf[:n]); werr != nil {
				return "", werr
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

func GenerateSalt(size int) ([]byte, error) {
	salt := make([]byte, size)
	_, err := rand.Read(salt)
	return salt, err
}

func GenerateKey(secret []byte, salt []byte) []byte {
	return argon2.IDKey(secret, salt, 6, 256*1024, 1, 32)
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func scrubString(s *string) {
	if s == nil || *s == "" {
		return
	}
	data := unsafe.Slice(unsafe.StringData(*s), len(*s))
	for i := range data {
		data[i] = 0
	}
	*s = ""
}

func validatePasswordStrength(password []byte) error {
	if len(password) < minPasswordLength {
		return fmt.Errorf("password must be at least %d characters long", minPasswordLength)
	}

	var hasUpper, hasLower, hasDigit, hasSymbol bool
	for _, r := range string(password) {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsSpace(r):
		default:
			hasSymbol = true
		}
	}

	classes := 0
	for _, ok := range []bool{hasUpper, hasLower, hasDigit, hasSymbol} {
		if ok {
			classes++
		}
	}

	if classes < 3 {
		return fmt.Errorf("password must contain at least 3 of the following: uppercase letters, lowercase letters, digits, symbols")
	}

	return nil
}

func readPasswordFromTerminal(confirm bool) ([]byte, error) {
	fd := int(os.Stdin.Fd())

	fmt.Print("Enter password: ")
	password, err := term.ReadPassword(fd)
	fmt.Println()
	if err != nil {
		return nil, fmt.Errorf("failed to read password: %v", err)
	}

	if confirm {
		fmt.Print("Confirm password: ")
		confirmation, err := term.ReadPassword(fd)
		fmt.Println()
		if err != nil {
			zeroBytes(password)
			return nil, fmt.Errorf("failed to read password confirmation: %v", err)
		}
		defer zeroBytes(confirmation)

		if !bytes.Equal(password, confirmation) {
			zeroBytes(password)
			return nil, fmt.Errorf("passwords do not match")
		}
	}

	return password, nil
}

func YubiKeyChallengeResponse(challenge []byte, slot int) ([]byte, error) {
	if _, err := exec.LookPath("ykchalresp"); err != nil {
		return nil, fmt.Errorf("ykchalresp not found in PATH; install yubikey-personalization (ykpers) to use --yubikey")
	}

	slotFlag := "-1"
	if slot == 2 {
		slotFlag = "-2"
	}

	cmd := exec.Command("ykchalresp", slotFlag, "-x", hex.EncodeToString(challenge))
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	fmt.Println("Waiting for YubiKey response (touch the device now if it requires confirmation)...")

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("yubikey challenge-response failed: %v (%s)", err, strings.TrimSpace(stderr.String()))
	}

	response, err := hex.DecodeString(strings.TrimSpace(stdout.String()))
	if err != nil {
		return nil, fmt.Errorf("failed to decode yubikey response: %v", err)
	}
	if len(response) == 0 {
		return nil, fmt.Errorf("yubikey returned an empty response")
	}

	return response, nil
}

func deriveSecret(password []byte, yubikeyEnabled bool, yubikeySlot int, challenge []byte) ([]byte, error) {
	if !yubikeyEnabled {
		secret := make([]byte, len(password))
		copy(secret, password)
		return secret, nil
	}

	response, err := YubiKeyChallengeResponse(challenge, yubikeySlot)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(response)

	secret := make([]byte, 0, len(password)+len(response))
	secret = append(secret, password...)
	secret = append(secret, response...)
	return secret, nil
}

func EncryptAndWriteToFile(data []byte, filePath string, password []byte, yubikeyEnabled bool, yubikeySlot int) error {
	salt, err := GenerateSalt(16)
	if err != nil {
		return err
	}

	var challenge []byte
	flags := byte(0)
	if yubikeyEnabled {
		challenge, err = GenerateSalt(yubikeyChallengeSize)
		if err != nil {
			return err
		}
		flags |= flagYubikey
	}

	secret, err := deriveSecret(password, yubikeyEnabled, yubikeySlot, challenge)
	if err != nil {
		return err
	}
	defer zeroBytes(secret)

	key := GenerateKey(secret, salt)
	defer zeroBytes(key)

	block, err := aes.NewCipher(key)
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

	header := []byte{fileVersion, flags}
	header = append(header, salt...)
	if yubikeyEnabled {
		header = append(header, challenge...)
	}

	ciphertext := gcm.Seal(nil, nonce, data, header)

	output := make([]byte, 0, len(header)+len(nonce)+len(ciphertext))
	output = append(output, header...)
	output = append(output, nonce...)
	output = append(output, ciphertext...)

	return atomicWriteFile(filePath, output, 0600)
}

func atomicWriteFile(filePath string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(filePath)
	tmp, err := os.CreateTemp(dir, ".tmp-"+filepath.Base(filePath)+"-*")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %v", err)
	}
	tmpPath := tmp.Name()

	success := false
	defer func() {
		if !success {
			tmp.Close()
			os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(perm); err != nil {
		return fmt.Errorf("failed to set permissions on temp file: %v", err)
	}

	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("failed to write temp file: %v", err)
	}

	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("failed to fsync temp file: %v", err)
	}

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %v", err)
	}

	if err := os.Rename(tmpPath, filePath); err != nil {
		return fmt.Errorf("failed to rename temp file into place: %v", err)
	}

	if dirFile, err := os.Open(dir); err == nil {
		_ = dirFile.Sync()
		dirFile.Close()
	}

	success = true
	return nil
}

func DecryptFileAndLoadHashes(filePath string, password []byte, yubikeyEnabled bool, yubikeySlot int) (map[string]string, error) {
	raw, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	if len(raw) < 2+16 {
		return nil, fmt.Errorf("hash file is corrupt or truncated")
	}

	version := raw[0]
	if version != fileVersion {
		return nil, fmt.Errorf("unsupported or tampered hash file version %d (expected %d)", version, fileVersion)
	}

	flags := raw[1]
	fileHasYubikey := flags&flagYubikey != 0
	if fileHasYubikey != yubikeyEnabled {
		return nil, fmt.Errorf("yubikey requirement mismatch: this hash file was created with --yubikey=%v; refusing to proceed with a different setting", fileHasYubikey)
	}

	offset := 2
	salt := raw[offset : offset+16]
	offset += 16

	var challenge []byte
	if fileHasYubikey {
		if len(raw) < offset+yubikeyChallengeSize {
			return nil, fmt.Errorf("hash file is corrupt or truncated")
		}
		challenge = raw[offset : offset+yubikeyChallengeSize]
		offset += yubikeyChallengeSize
	}

	header := raw[:offset]

	secret, err := deriveSecret(password, yubikeyEnabled, yubikeySlot, challenge)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(secret)

	key := GenerateKey(secret, salt)
	defer zeroBytes(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(raw) < offset+nonceSize {
		return nil, fmt.Errorf("hash file is corrupt or truncated")
	}

	nonce := raw[offset : offset+nonceSize]
	offset += nonceSize
	ciphertext := raw[offset:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, header)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: wrong password/yubikey response, or the hash file has been tampered with: %v", err)
	}
	defer zeroBytes(plaintext)

	storedHashes := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(plaintext))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}
		hash := parts[0]
		if len(hash) != sha512HexLen {
			continue
		}
		pathBytes, err := hex.DecodeString(parts[1])
		if err != nil {
			continue
		}
		storedHashes[string(pathBytes)] = hash
	}

	return storedHashes, scanner.Err()
}

type fileEntry struct {
	absPath string
	relPath string
}

func collectFiles(rootDir string) ([]fileEntry, error) {
	var entries []fileEntry
	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			fmt.Printf("Skipping symlink (not followed): %s\n", path)
			return nil
		}

		relPath, err := filepath.Rel(rootDir, path)
		if err != nil {
			return err
		}

		entries = append(entries, fileEntry{absPath: path, relPath: filepath.ToSlash(relPath)})
		return nil
	})
	return entries, err
}

func HashAllFilesInDirectory(rootDir string, verbose bool, workers int) (map[string]string, error) {
	entries, err := collectFiles(rootDir)
	if err != nil {
		return nil, err
	}

	total := len(entries)
	if workers < 1 {
		workers = 1
	}
	if workers > total && total > 0 {
		workers = total
	}

	type result struct {
		relPath string
		hash    string
		err     error
	}

	jobs := make(chan fileEntry, workers*2)
	results := make(chan result, workers*2)

	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for e := range jobs {
				hash, herr := HashFile(e.absPath)
				results <- result{relPath: e.relPath, hash: hash, err: herr}
			}
		}()
	}

	go func() {
		for _, e := range entries {
			jobs <- e
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	hashes := make(map[string]string, total)
	var firstErr error
	processed := 0
	lastPrint := time.Now()

	for r := range results {
		processed++
		if r.err != nil {
			if firstErr == nil {
				firstErr = r.err
			}
			continue
		}

		hashes[r.relPath] = r.hash

		if verbose {
			fmt.Printf("Hashed: %s\n", r.relPath)
		} else if processed == total || time.Since(lastPrint) >= 50*time.Millisecond {
			printProgressBar(processed, total)
			lastPrint = time.Now()
		}
	}

	if !verbose {
		fmt.Println()
	}

	if firstErr != nil {
		return nil, firstErr
	}
	return hashes, nil
}

func printProgressBar(current, total int) {
	const progressBarWidth = 40

	if total <= 0 {
		fmt.Printf("\r[%s] %d/%d", strings.Repeat(" ", progressBarWidth), current, total)
		return
	}

	progress := float64(current) / float64(total)
	if progress < 0 {
		progress = 0
	}
	if progress > 1 {
		progress = 1
	}

	barWidth := int(progress * progressBarWidth)
	if barWidth > progressBarWidth {
		barWidth = progressBarWidth
	}

	fmt.Printf("\r[%s%s] %d/%d",
		strings.Repeat("=", barWidth),
		strings.Repeat(" ", progressBarWidth-barWidth),
		current,
		total,
	)
}

func main() {
	var (
		rootDir        = flag.String("dir", "", "The directory to hash and monitor for integrity")
		checkIntegrity = flag.Bool("check", false, "Check integrity of the selected directory")
		passwordFlag   = flag.String("password", "", "Encryption password for hashes storage (INSECURE: visible in shell history/process list; Prefer omitting it and entering it at the interactive prompt instead.)")
		verbose        = flag.Bool("verbose", false, "Enable verbose output")
		yubikeyEnabled = flag.Bool("yubikey", false, "Require a YubiKey (HMAC-SHA1 challenge-response) as a second factor in addition to the password")
		yubikeySlot    = flag.Int("yubikey-slot", 2, "YubiKey challenge-response slot to use (1 or 2)")
		workers        = flag.Int("workers", runtime.NumCPU(), "Number of concurrent workers used to hash files (higher can help on large directories, especially on fast/SSD storage)")
	)
	flag.Parse()

	if *workers < 1 {
		fmt.Println("Error: --workers must be at least 1")
		return
	}

	if *rootDir == "" {
		fmt.Println("Error: --dir is required")
		return
	}

	if *yubikeySlot != 1 && *yubikeySlot != 2 {
		fmt.Println("Error: --yubikey-slot must be 1 or 2")
		return
	}

	if *passwordFlag != "" {
		fmt.Println("Warning: --password exposes your password via the process list and shell history. Prefer omitting it and entering it at the interactive prompt instead.")
	}

	var password []byte
	if *passwordFlag != "" {
		password = []byte(*passwordFlag)
		scrubString(passwordFlag)
	} else {
		pw, err := readPasswordFromTerminal(!*checkIntegrity)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}
		password = pw
	}
	defer zeroBytes(password)

	if err := validatePasswordStrength(password); err != nil {
		fmt.Printf("Error: weak password: %v\n", err)
		return
	}

	absRootDir, err := filepath.Abs(*rootDir)
	if err != nil {
		fmt.Printf("Error resolving directory path: %v\n", err)
		return
	}

	rootDirClean := filepath.Clean(absRootDir)
	parentDir := filepath.Dir(rootDirClean)
	hashFileName := fmt.Sprintf("%s.hashes.enc", filepath.Base(rootDirClean))
	hashFilePath := filepath.Join(parentDir, hashFileName)

	if !*checkIntegrity {
		storedHashes, err := HashAllFilesInDirectory(rootDirClean, *verbose, *workers)
		if err != nil {
			fmt.Printf("Error hashing files: %v\n", err)
			return
		}

		keys := make([]string, 0, len(storedHashes))
		for file := range storedHashes {
			keys = append(keys, file)
		}
		sort.Strings(keys)

		var hashString strings.Builder
		for _, file := range keys {
			if _, err := fmt.Fprintf(&hashString, "%s %s\n", storedHashes[file], hex.EncodeToString([]byte(file))); err != nil {
				fmt.Printf("Error writing hash data: %v\n", err)
				return
			}
		}

		if err := EncryptAndWriteToFile([]byte(hashString.String()), hashFilePath, password, *yubikeyEnabled, *yubikeySlot); err != nil {
			fmt.Printf("Error encrypting and writing to the hash file: %v\n", err)
			return
		}

		fmt.Printf("Hashes stored in %s\n", hashFilePath)
		if *yubikeyEnabled {
			fmt.Printf("This database now requires the same YubiKey (slot %d) to verify integrity.\n", *yubikeySlot)
			fmt.Println("Keep a backup YubiKey configured with the same secret in case this one is lost or destroyed.")
		}
	} else {
		storedHashes, err := DecryptFileAndLoadHashes(hashFilePath, password, *yubikeyEnabled, *yubikeySlot)
		if err != nil {
			fmt.Printf("Error decrypting and loading stored hashes: %v\n", err)
			return
		}

		recalculatedHashes, err := HashAllFilesInDirectory(rootDirClean, *verbose, *workers)
		if err != nil {
			fmt.Printf("Error recalculating hashes: %v\n", err)
			return
		}

		integrityFailed := false

		for file, recalculatedHash := range recalculatedHashes {
			storedHash, ok := storedHashes[file]
			if !ok || storedHash != recalculatedHash {
				if !ok {
					fmt.Printf("New file detected: %s\n", filepath.FromSlash(file))
				} else {
					fmt.Printf("Integrity check failed for: %s\n", filepath.FromSlash(file))
				}
				integrityFailed = true
			}
		}

		for file := range storedHashes {
			if _, ok := recalculatedHashes[file]; !ok {
				fmt.Printf("Deleted file detected: %s\n", filepath.FromSlash(file))
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