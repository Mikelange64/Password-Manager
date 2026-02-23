import pytest
import json
from pathlib import Path
from unittest import mock
from types import SimpleNamespace
import src.passwords as passwords


@pytest.fixture
def vault_dir(tmp_path, monkeypatch):
    # Point the module's VAULT constant to a temp file
    fake_vault = tmp_path / '.vault.enc'
    monkeypatch.setattr(passwords, 'VAULT', fake_vault)
    return tmp_path


@pytest.fixture
def initialized_vault(vault_dir):
    # Build a real encrypted vault with a known master password
    master_pw = "C0rr3ct-H0rse-Battery!"
    key, salt = passwords._derive_key_from_password(master_pw)
    vault_data = {'passwords': []}
    passwords._encrypt_vault(key, salt, json.dumps(vault_data))
    return vault_dir, master_pw, key, salt


@pytest.fixture
def vault_with_entries(initialized_vault):
    vault_dir, master_pw, key, salt = initialized_vault
    vault_data = {
        'passwords': [
            {'service': 'github', 'username': 'alice', 'password': 'secret123'},
            {'service': 'spotify', 'username': 'alice', 'password': 'music456'},
        ]
    }
    passwords._encrypt_vault(key, salt, json.dumps(vault_data))
    return vault_dir, master_pw, key, salt