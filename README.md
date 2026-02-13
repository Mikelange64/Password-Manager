Overview
Build a secure command-line password manager with encryption to safely store and retrieve passwords.

Core Requirements

1. Master Password Setup
    • First-time initialization 
    • Create master password 
    • Confirm master password (must match) 
    • Initialize encrypted vault file 
    • Never store master password (use for encryption key derivation only) 
Example Command:
python passwords.py init

------------------------------------------------------------------------------------------------------------------------

2. Add Passwords
    • Unlock vault with master password 
    • Enter service name, username, password 
    • Optional: auto-generate secure password 
    • Optional: store URL 
    • Save to encrypted vault 
Example Command:
python passwords.py add
Interactive Prompts:
Master password: ********
Service name: GitHub
Username: alice@email.com
Password: (leave empty to generate)
✅ Generated secure password: aB9$mK2#pL5@qR8
Save to vault? (y/n): y

------------------------------------------------------------------------------------------------------------------------

3. Retrieve Passwords
    • Search by service name (case-insensitive) 
    • Unlock with master password 
    • Display username and password 
    • Optional: copy password to clipboard 
    • Optional: show URL 
Example Command:
python passwords.py get github

------------------------------------------------------------------------------------------------------------------------

4. List All Services
    • Show all stored services 
    • Display service name and username 
    • Don't show passwords in list view 
    • Require master password to unlock 
Example Command:
python passwords.py list

------------------------------------------------------------------------------------------------------------------------

5. Generate Strong Passwords
    • Create cryptographically secure passwords 
    • Customizable length (default 16) 
    • Options for symbols, numbers, uppercase, lowercase 
    • Display password strength indicator 
    • Copy to clipboard option 
Example Commands:
python passwords.py generate
python passwords.py generate --length 20 --no-symbols

------------------------------------------------------------------------------------------------------------------------

6. Update and Delete
    • Update username or password for existing service 
    • Delete service credentials with confirmation 
    • Require master password for both operations 
Example Commands:
python passwords.py update github --username newemail@example.com
python passwords.py update github --password
python passwords.py delete netflix

------------------------------------------------------------------------------------------------------------------------

7. Export and Import
    • Export encrypted backup of entire vault 
    • Import vault from backup file 
    • Require master password for both operations 
    • Maintain encryption in backup 
Example Commands:
python passwords.py export --output passwords_backup.json.enc
python passwords.py import --file passwords_backup.json.enc

------------------------------------------------------------------------------------------------------------------------

# Data Structure

Vault File (vault.enc) - ENCRYPTED BINARY:
Contains encrypted JSON:
{
  "services": {
    "github": {
      "username": "alice@email.com",
      "password": "aB9$mK2#pL5@qR8",
      "url": "https://github.com",
      "created": "2025-01-20T10:30:00",
      "modified": "2025-01-20T10:30:00"
    },
    "gmail": {
      "username": "alice@gmail.com",
      "password": "xY3$nM8@kP2#vQ9",
      "url": "https://mail.google.com",
      "created": "2025-01-18T14:20:00",
      "modified": "2025-01-18T14:20:00"
    }
  }
}


------------------------------------------------------------------------------------------------------------------------

# Security Requirements (CRITICAL)
MUST IMPLEMENT:
    1. Encryption: Use cryptography library (Fernet symmetric encryption) 
    2. Key Derivation: Derive encryption key from master password using SHA-256 
    3. No Plain Text: NEVER store passwords in plain text anywhere 
    4. No Master Password Storage: NEVER save master password to disk 
    5. Secure Random: Use secrets module for password generation (NOT random) 
    6. Hidden Input: Use getpass to hide password input from terminal 

Installation Required:
pip install cryptography

Required Modules
    • cryptography - Fernet encryption/decryption (ONLY external dependency) 
    • secrets - cryptographically secure random generation 
    • string - character sets for password generation 
    • json - data structure serialization 
    • getpass - hide password input in terminal 
    • hashlib - derive encryption key from master password 
    • base64 - encode key for Fernet 
    • datetime - timestamps 
    • sys or argparse - command-line arguments 

------------------------------------------------------------------------------------------------------------------------
    
Encryption Implementation Guide

Key Derivation:
    • Use SHA-256 to hash master password 
    • Result is 32-byte key 
    • Base64 encode for Fernet compatibility 
Encryption Process:
    1. Get master password from user 
    2. Derive encryption key from master password 
    3. Serialize vault data to JSON string 
    4. Encrypt JSON string using Fernet 
    5. Write encrypted binary data to vault.enc 
Decryption Process:
    1. Get master password from user 
    2. Derive same encryption key 
    3. Read encrypted binary data from vault.enc 
    4. Decrypt using Fernet 
    5. Parse JSON string back to dictionary 
Wrong Password:
    • If wrong master password is used 
    • Decryption will fail with exception 
    • Display error message 
    • Exit without showing vault contents 

------------------------------------------------------------------------------------------------------------------------

Password Generation Requirements
Strong Password Criteria:
    • Minimum 12 characters 
    • Mix of uppercase and lowercase letters 
    • Include numbers 
    • Include symbols (optional) 
    • Use secrets.choice() not random.choice() 
Strength Checking:
    • Very Weak: < 8 chars or all same type 
    • Weak: 8-11 chars, missing character types 
    • Medium: 12-15 chars, 3+ character types 
    • Strong: 16-19 chars, 4+ character types 
    • Very Strong: 20+ chars, all character types 

------------------------------------------------------------------------------------------------------------------------

Bonus Features
    1. Password Strength Checker
        ◦ Analyze any password for strength 
        ◦ Provide improvement suggestions 
        ◦ Check against common password list 
    2. Clipboard Auto-Clear
        ◦ Copy password to clipboard 
        ◦ Automatically clear after 30 seconds 
        ◦ Notify user when cleared 
        ◦ (Requires pyperclip library) 
    3. Password History
        ◦ Track creation and modification dates 
        ◦ Warn if password is old (> 90 days) 
        ◦ Suggest updating old passwords 
    4. Breach Check
        ◦ Check if password appears in common password lists 
        ◦ Maintain local list of compromised passwords 
        ◦ Warn user if password is weak or compromised 
    5. Categories and Tags
        ◦ Organize services by category (work, personal, etc.) 
        ◦ Add tags to services 
        ◦ Filter list by category or tag 
    6. Two-Factor Backup Codes
        ◦ Store 2FA backup codes securely 
        ◦ Encrypted along with passwords 
        ◦ Retrieve when needed 

------------------------------------------------------------------------------------------------------------------------

Success Criteria
    • Vault file is completely unreadable without master password 
    • Wrong master password NEVER decrypts vault (fails with error) 
    • Generated passwords are cryptographically secure 
    • No passwords stored in plain text ANYWHERE (including temp files, logs) 
    • Handles multiple vaults (different files for different users) 
    • Encryption/decryption is fast (< 1 second) 
    • No memory leaks or password remnants in RAM 

Security Best Practices to Follow
    • Clear password variables from memory after use 
    • Don't log passwords or master password 
    • Don't display passwords unless explicitly requested 
    • Confirm before destructive operations 
    • Handle Ctrl+C gracefully (don't leave vault unlocked) 
    • Set proper file permissions on vault file (user read/write only) 

What This Demonstrates
    • Cryptography and encryption/decryption 
    • Secure password handling 
    • Key derivation from passwords 
    • Cryptographically secure random generation 
    • Binary file handling 
    • Security best practices 
    • User input validation 
    • Hidden password input 
    • Error handling (wrong master password) 
    • Data serialization (JSON to bytes) 
