import argparse
import secrets
import bcrypt
import hashlib
from zxcvbn import zxcvbn
from getpass import getpass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description='Password Manager')
    subparser = parser.add_subparsers(dest='commands', help='Available commands')

    
