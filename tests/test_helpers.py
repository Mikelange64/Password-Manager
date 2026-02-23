import pytest
import json
from pathlib import Path
from unittest import mock
from types import SimpleNamespace
import src.passwords as passwords

class TestValidatePassword:

    def test_weak_password(self):
        score, response = passwords._validate_password("123456")
        assert score < 3
        assert "Weak" in response

    def test_strong_password(self):
        score, response = passwords._validate_password("C0rr3ct-H0rse-Battery!")
        assert score >= 3

    def test_returns_score_and_string(self):
        result = passwords._validate_password("somepassword")
        assert isinstance(result, tuple)
        assert isinstance(result[0], int)
        assert isinstance(result[1], str)


class TestPasswordHashing:

    def test_hash_and_verify(self):
        pw = "MyPassword123!"
        hashed = passwords._get_password_hash(pw)
        assert passwords._verify_password(pw, hashed)

    def test_wrong_password_fails(self):
        hashed = passwords._get_password_hash("correct")
        assert not passwords._verify_password("wrong", hashed)


class TestDeriveKey:

    def test_same_password_same_salt_gives_same_key(self):
        pw = "test-password"
        key1, salt = passwords._derive_key_from_password(pw)
        key2, _ = passwords._derive_key_from_password(pw, salt)
        assert key1 == key2

    def test_different_salts_give_different_keys(self):
        pw = "test-password"
        key1, _ = passwords._derive_key_from_password(pw)
        key2, _ = passwords._derive_key_from_password(pw)
        assert key1 != key2

    def test_returns_32_byte_key(self):
        key, salt = passwords._derive_key_from_password("password")
        assert len(key) == 32


class TestConvertToBytes:

    def test_encrypt_then_decrypt_roundtrip(self):
        key, _ = passwords._derive_key_from_password("password")
        original = "hello world"
        encrypted = passwords._encryptor(key, original)
        decrypted = passwords._decryptor(key, encrypted)
        assert decrypted == original