<div align="center">
<br/>

<img src="background.png" width="600" />
<br/>

## A tool for monitoring the integrity of important files

</div>

<!-- DESCRIPTION -->
## Description:

This tool checks the integrity of files in a selected directory and its subdirectories by hashing and securely storing file data. It monitors for any changes or modifications, identifying any unauthorized alterations or corruption in files. This is especially useful for critical system files, configuration files, the bootloader of an operating system, or sensitive documents. If an attacker tries to modify system files or data on the device (e.g., to plant malware or backdoors), these changes would be detected during an integrity check. It's advised to run this tool from a live USB ([Tails OS](https://tails.net))

<!-- FEATURES -->
## Features:

- Hashes all files in a selected directory and its subdirectories
- YubiKey support
- Encrypts hashes for storage using an encryption key derived from a password + YubiKey challenge-response
- Scans for alterations in a directory using an encrypted hashes file
- It can detect [evil maid attacks](https://www.kicksecure.com/wiki/AEM#Introduction) by monitoring the integrity of a system's ``` /boot ``` partition

## Technical details:

- AES-256-GCM for encryption
- YubiKey HMAC-SHA1 challenge-response for 2FA
- SHA-512 for hashing using 1MB chunks
- Argon2id for key derivation using 1 thread, 256MB of memory, and 6 iterations

<!-- INSTALLATION -->
## Installation:

### Option 1:

[Download](https://github.com/umutcamliyurt/IntegrityGuard/releases) from releases

### Option 2:

Run the following command:

    $ go install -v github.com/umutcamliyurt/IntegrityGuard@latest

<!-- USAGE -->
## Usage:

### Options:

```
Usage of ./IntegrityGuard:
  -check
    	Check integrity of the selected directory
  -dir string
    	The directory to hash and monitor for integrity
  -password string
    	Encryption password for hashes storage (INSECURE: visible in shell history/process list; Prefer omitting it and entering it at the interactive prompt instead.)
  -verbose
    	Enable verbose output
  -workers int
    	Number of concurrent workers used to hash files (higher can help on large directories, especially on fast/SSD storage) (default 6)
  -yubikey
    	Require a YubiKey (HMAC-SHA1 challenge-response) as a second factor in addition to the password
  -yubikey-slot int
    	YubiKey challenge-response slot to use (1 or 2) (default 2)
```
### Generating hashes of a directory:

```
./IntegrityGuard -yubikey -dir Documents
Enter password: 
Confirm password: 
[========================================] 2698/2698
Waiting for YubiKey response (touch the device now if it requires confirmation)...
Hashes stored in /home/user/Documents.hashes.enc
This database now requires the same YubiKey (slot 2) to verify integrity.
Keep a backup YubiKey configured with the same secret in case this one is lost or destroyed.
```
### Checking the integrity of a directory:

#### Pass:

```
./IntegrityGuard -yubikey -dir Documents -check
Enter password: 
Waiting for YubiKey response (touch the device now if it requires confirmation)...
[========================================] 2698/2698
Integrity check successful. All files are verified. ✔️
```
#### Fail:

```
./IntegrityGuard -yubikey -dir Documents -check
Enter password: 
Waiting for YubiKey response (touch the device now if it requires confirmation)...
[========================================] 2698/2698
Integrity check failed for: Customer_Database_Export.pdf
New file detected: Legal/Contracts/Agreement.txt
Deleted file detected: Research/Security_Analysis/latest.doc
Some files are missing or have been modified. ❌
```

<!-- LICENSE -->
## License
Distributed under the MIT License. See `LICENSE` for more information.