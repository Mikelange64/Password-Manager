import pytest
import json
from pathlib import Path
from unittest import mock
from types import SimpleNamespace
import src.passwords as passwords

class TestVaultEncryption:

    def test_encrypt_and_decrypt_vault(self, vault_dir, monkeypatch):
        fake_vault = vault_dir / '.vault.enc'
        monkeypatch.setattr(passwords, 'VAULT', fake_vault)

        key, salt = passwords._derive_key_from_password("masterpassword")
        data = {'passwords': [{'service': 'github', 'username': 'bob'}]}
        passwords._encrypt_vault(key, salt, json.dumps(data))

        result = passwords._decrypt_vault(key)
        assert result == data

    def test_wrong_key_raises(self, initialized_vault):
        wrong_key, _ = passwords._derive_key_from_password("wrongpassword")
        with pytest.raises(Exception):  # AES-GCM raises on bad key
            passwords._decrypt_vault(wrong_key)