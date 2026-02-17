import argparse
import secrets
import bcrypt
import json
import string
from zxcvbn import zxcvbn
from getpass import getpass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type
from pathlib import Path

ROOT = Path(__file__).parent.resolve()
VAULT = ROOT / '.vault.enc'

def _encryptor(key: bytes, message: str) -> bytes:
    nonce = secrets.token_bytes(12)
    aes = AESGCM(key)
    return nonce + aes.encrypt(nonce, message.encode(), None) # encrypted message

def _decryptor(key:bytes, message:bytes) -> str:
    nonce = message[:12]
    ciphertext = message[12:]
    aes = AESGCM(key)
    return aes.decrypt(nonce, ciphertext, None).decode() # decrypted message

def _encrypt_vault(key:bytes, salt:bytes, vault_string: str):
    encrypted_vault = _encryptor(key, vault_string)
    with VAULT.open('wb') as f:
        f.write(salt)
        f.write(encrypted_vault)

def _decrypt_vault(key:bytes) -> dict:
    vault_bytes = VAULT.read_bytes()
    encrypted_vault = vault_bytes[16:] # remove salt before decryption
    decrypted_vault = _decryptor(key, encrypted_vault)
    return json.loads(decrypted_vault)

def _validate_password(pw: str) -> tuple[int, str]:
    result = zxcvbn(pw)
    score = result['score']
    if score == 3:
        response = f'Strong password, score: {score} '
    elif score == 4:
        response = f'Very strong password, score {score}'
    else:
        feedback = result.get('feedback')
        warning = feedback.get('warning', '')
        suggestions = feedback.get('suggestions', '')
        response = (f'Weak password, score: {score}\n'
                    f'warning: {warning if warning else None}\n'
                    f'suggestions: {". ".join(suggestions)}')
    return score, response

def _get_password_hash(pw: str) -> bytes:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt())

def _verify_password(pw_attempt: str, pw_hash: bytes) -> bool:
    return bcrypt.checkpw(pw_attempt.encode(), pw_hash)

def _derive_key_from_password(pw: str, salt=None) -> tuple[bytes, bytes]:
    if salt is None:
        salt = secrets.token_bytes(16)

    key = hash_secret_raw(
        secret = pw.encode(),
        salt = salt,
        time_cost  = 2,
        memory_cost = 65536,
        parallelism = 1,
        hash_len = 32,
        type = Type.ID
    )
    return key, salt

def _save(key, salt, vault):
    vault_string = json.dumps(vault)
    _encrypt_vault(key, salt, vault_string)

def _process_master_password():
    master_pw = getpass('Master password: ')
    with VAULT.open('rb') as f:
        salt = f.read(16)

    key = _derive_key_from_password(master_pw, salt)[0]
    vault = None
    while vault is None:
        try:
            vault = _decrypt_vault(key)  # if password is wrong AES-GCM will raise an error
            if 'passwords' not in vault:  #
                raise ValueError("Vault corrupted")  # checks if files has been corrupted/tampered with, not a wrong password issue
        except Exception:
            master_pw = getpass("Incorrect password, try again: ")
            key = _derive_key_from_password(master_pw, salt)[0]
            vault = None
    return key, salt, vault

def initialize_vault(args=None):
    print('⚠️ WARNING: MASTER PASSWORD IS NOT RECOVERABLE. PLEASE WRITE IT DOWN SOMEWHERE SAFE.')
    print('IF YOU FORGET YOUR MASTER PASSWORD, YOU WILL BE LOCKED OUT OF THE PASSWORD MANAGER.')
    password = getpass('Create a master password: ')
    pw_score, comment = _validate_password(password)
    print(comment)

    while pw_score < 3:
        password = getpass('Please try another password: ')
        pw_score, comment = _validate_password(password)
        print(comment)

    confirm = getpass('Confirm your password: ')
    hashed = _get_password_hash(password)

    while not _verify_password(confirm, hashed):
        confirm = getpass('Passwords do not match, please try again: ')

    key, salt = _derive_key_from_password(password)
    vault_data = {'passwords': []}
    vault_string = json.dumps(vault_data)
    _encrypt_vault(key, salt, vault_string)
    print('Your vault has been created!')

def add_password(args=None):
    key, salt, vault = _process_master_password()

    service = input('Service name: ').lower()
    username = input('Username: ')
    generate = input('1. Generate password\n'
                     '2. Enter password\n'
                     '(1 or 2): ')
    while generate not in ('1', '2'):
        generate = input('Invalid choice. Please select one of the two options (1 or 2):')

    if generate == '1':
        password = secrets.token_urlsafe(16)
    else:
        password = getpass('Password: ')

    comment = _validate_password(password)[1]
    print(comment)
    confirm = getpass('Confirm your password: ')
    hashed = _get_password_hash(password)

    while not _verify_password(confirm, hashed):
        confirm = getpass('Passwords do not match, please try again: ')

    vault_entry = {
        "service" : service,
        "username" : username,
        "password" : password
    }

    save = input('Do you want to save this entry to your vault?[y/N]: ')
    if save == 'y':
        vault['passwords'].append(vault_entry)
        _save(key, salt, vault)
        print('New password has been added!')

def get_password(args):
    key, salt, vault = _process_master_password()
    service_name = getattr(args, 'service', None)

    if not vault['passwords']:
        print('You have not saved any passwords.')
        return
    if args.all and service_name is not None:
        print('Please either select "-all" to see all your passwords, or "--service" followed by the service you want to see.')
        return

    if args.all:
        services_to_show = vault['passwords']
    else:
        services_to_show = [entry for entry in vault['passwords'] if service_name.lower() == entry['service']]
        if not services_to_show:
            print('No entry found for this service.')
            return

    for s in services_to_show:
        for k, v in s.items():
            print(f'{k} : {v}')
        print()

def list_services(args=None):
    _, _, vault = _process_master_password()

    for entry in vault['passwords']:
        print(f"Service: {entry['service']}")
        print(f"Username: {entry['username']}")

def generate(args):
    length = getattr(args, 'length', 22)
    no_symbol = getattr(args, 'no_symbol', False)

    if no_symbol:
        alphabet = string.ascii_letters + string.digits
    else:
        alphabet = string.ascii_letters + string.digits + string.punctuation

    pw = "".join(secrets.choice(alphabet) for _ in range(length))
    print(f"Password: {pw}")

    print(f'Password :{pw}')
    return

def update(args):
    key, salt, vault = _process_master_password()
    entry = args.entry.lower()
    password = getattr(args, 'password', None)
    username = getattr(args, 'username', None)

    if password:
        confirm = getpass('Confirm your password: ')
        hashed = _get_password_hash(password)
        while not _verify_password(confirm, hashed):
            confirm = getpass('Passwords do not match, please try again: ')

    if not args.delete:
        found = False
        for p in vault['passwords']:
            if p['service'] == entry:
                found = True
                if password:
                    p['password'] = password
                if username:
                    p['username'] = username
        if not found:
            print('Entry not in the vault.')
            return

    else:
        mock = [p for p in vault['passwords'] if p['service'] != entry]
        if len(mock) == len(vault['password']):
            print('Entry not in the vault.')
            return
        vault['passwords'] = mock

    update_vault = input('Do you want to save this update?[y/N]: ')
    if update_vault == 'y':
        _save(key, salt, vault)
        print('Vault has been updated!')

def transfer(args):
    key, salt, vault = _process_master_password()
    file = Path(args.file)

    if args.export_file and args.import_file:
        print('You cannot import and export a file at the same time. Please select one.')
        return

    if args.export_file:
        with file.open('w') as f:
            json.dump(vault, f, indent=2)
        print(f'Your passwords have been exported to {file}')
        print("⚠️  Warning: Exported file is NOT encrypted.")
        return

    if args.import_file:
        if not file.exists():
            print(f"Error: The file {file} does not exist.")
            return

        data = file.read_text()
        _encrypt_vault(key, salt, data)

        print('File successfully imported')
        return

def main():
    parser = argparse.ArgumentParser(description='Password Manager')
    subparser = parser.add_subparsers(dest='commands', help='Available commands')

    # ====================== MASTER PASSWORD ======================
    init = subparser.add_parser('init', help='Create your master password and initialize your vault')
    init.set_defaults(func=initialize_vault)

    # ======================== ADD PASSWORD =======================
    add = subparser.add_parser('add', help='Add passwords in your vault')
    add.set_defaults(func=add_password)

    # ======================== GET PASSWORD =======================
    get = subparser.add_parser('get', help='Retrieve password from your vault')
    get.add_argument('--service', type=str, help='Password you want to retrieve')
    get.add_argument('--all', action='store_true', help='Retrieve all passwords (not recommended)')
    get.set_defaults(func=get_password)

    # ======================= LIST SERVICES =======================
    list_all = subparser.add_parser('list', help='List all services stored in your vault')
    list_all.set_defaults(func=list_services)

    # ===================== GENERATE PASSWORD =====================
    generate = subparser.add_parser('generate', help='Generate passwords')
    generate.add_argument('--length', type=int, help='Password length')
    generate.add_argument('--no-symbol', action='store_true', help='No symbols in your password.')
    generate.set_defaults(func=generate)

    # ======================== UPDATE/DELETE ======================
    update = subparser.add_parser('update', help='Update passwords')
    update.add_argument('entry', type=str, required=True, help='Entry to update')
    update.add_argument('--delete', action='store_true', help='Delete entry')
    update.add_argument('--username', type=str, help='Update username')
    update.add_argument('--password', type=str, help='Update password')
    update.set_defaults(func=update)

    # ======================= DATA TRANSFER =======================
    data = subparser.add_parser('data', help='Update passwords')
    data.add_argument('--export-file', action='store_true', help='Export file')
    data.add_argument('--import-file', action='store_true', help='Import file')
    data.add_argument('--file', type=str, required=True, help='File to import/export')
    data.set_defaults(func=transfer)

    args = parser.parse_args()

    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()