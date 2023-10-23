# IntegrityGuard

<img src="background.png" width="1200">

## A very secure tool for monitoring integrity of important files

<!-- DESCRIPTION -->
## Description:

This tool checks integrity of files in a selected directory and its subdirectories by hashing and securely storing file data. It monitors for any changes or modifications, identifying any unauthorized alterations or corruption in files. This is especially useful for critical system files, configuration files, bootloader of an operating system, or sensitive documents. If an attacker tries to modify system files or data on the device (e.g., to plant malware or backdoors), these changes would be detected during an integrity check. It's advised to run this tool from a live USB ([Tails OS](https://tails.net))

<!-- FEATURES -->
## Features:

- Checksums all files in a selected directory and its subdirectories

- Encrypts directory hashes for storage

- Scans for alterations in a directory using encrypted hash file

- Catches an [evil maid attack](https://www.kicksecure.com/wiki/AEM#Introduction) by monitoring integrity of a system's ``` /boot ``` partition


- Able to check integrity of an entire SSD for alterations

## Technical details:

- AES-256-GCM for encryption
- SHA-512 for hashing using 1MB chunks
- Argon2id for key derivation using 1 thread, 64MB of memory and 4 iterations.

<!-- INSTALLATION -->
## Installation:

### Option 1:

[Download](https://github.com/Nemesis0U/IntegrityGuard/releases) from releases

### Option 2:
Run the following command:

    $ go install -v github.com/Nemesis0U/IntegrityGuard@latest

<!-- USAGE -->
## Usage:

### Options:

```
Usage of IntegrityGuard:
  -check
    	Check integrity of the selected directory
  -dir string
    	The directory to hash and monitor for integrity
  -interactive
    	Enable interactive mode
  -password string
    	Encryption password for checksum storage (default "empty")
  -verbose
    	Enable verbose output
```
<!-- EXAMPLE -->
### Example:

### Generating checksum of a directory:

```
./IntegrityGuard -dir Documents -password 123456

██╗███╗   ██╗████████╗███████╗ ██████╗ ██████╗ ██╗████████╗██╗   ██╗
██║████╗  ██║╚══██╔══╝██╔════╝██╔════╝ ██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝
██║██╔██╗ ██║   ██║   █████╗  ██║  ███╗██████╔╝██║   ██║    ╚████╔╝ 
██║██║╚██╗██║   ██║   ██╔══╝  ██║   ██║██╔══██╗██║   ██║     ╚██╔╝  
██║██║ ╚████║   ██║   ███████╗╚██████╔╝██║  ██║██║   ██║      ██║   
╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝   
                                                                    
 ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗                           
██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗                          
██║  ███╗██║   ██║███████║██████╔╝██║  ██║                          
██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║                          
╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝                          
 ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝                           
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     

[========================================] 2698/2698
Hashes stored in Documents.hashes.enc

```

### Checking integrity of a directory:

```
./IntegrityGuard -dir Documents -password 123456 -check

██╗███╗   ██╗████████╗███████╗ ██████╗ ██████╗ ██╗████████╗██╗   ██╗
██║████╗  ██║╚══██╔══╝██╔════╝██╔════╝ ██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝
██║██╔██╗ ██║   ██║   █████╗  ██║  ███╗██████╔╝██║   ██║    ╚████╔╝ 
██║██║╚██╗██║   ██║   ██╔══╝  ██║   ██║██╔══██╗██║   ██║     ╚██╔╝  
██║██║ ╚████║   ██║   ███████╗╚██████╔╝██║  ██║██║   ██║      ██║   
╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝   
                                                                    
 ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗                           
██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗                          
██║  ███╗██║   ██║███████║██████╔╝██║  ██║                          
██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║                          
╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝                          
 ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝                           
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     

[========================================] 2698/2698

Integrity check failed for: Customer_Database_Export.pdf
New file detected: test Legal/Contracts/Agreement.txt
Deleted file detected: Research/Security_Analysis/latest.doc
Integrity check failed. Some files are missing or have been modified. ❌

```
<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE` for more information.
