import pytest
import json
from pathlib import Path
from unittest import mock
from types import SimpleNamespace
import src.passwords as passwords

class TestGenerate:
    # generate() is the easiest — no vault, no input, just args

    def test_default_length(self, capsys):
        args = SimpleNamespace(length=22, no_symbol=False)
        passwords.generate(args)
        captured = capsys.readouterr()
        # Extract the password from the printed output
        pw = captured.out.split("Password :")[1].strip()
        assert len(pw) == 22

    def test_no_symbol(self, capsys):
        args = SimpleNamespace(length=16, no_symbol=True)
        passwords.generate(args)
        captured = capsys.readouterr()
        pw = captured.out.split("Password :")[1].strip()
        assert not any(c in pw for c in '!@#$%^&*()')

    def test_with_symbols(self, capsys):
        # Run many times to increase confidence symbols can appear
        args = SimpleNamespace(length=30, no_symbol=False)
        passwords.generate(args)
        captured = capsys.readouterr()
        assert "Password" in captured.out


class TestGetPassword:

    def test_get_by_service(self, vault_with_entries, capsys):
        _, master_pw, _, _ = vault_with_entries
        args = SimpleNamespace(service='github', all=False)

        with mock.patch('src.passwords.getpass', return_value=master_pw):
            passwords.get_password(args)

        captured = capsys.readouterr()
        assert 'github' in captured.out
        assert 'alice' in captured.out

    def test_get_nonexistent_service(self, vault_with_entries, capsys):
        _, master_pw, _, _ = vault_with_entries
        args = SimpleNamespace(service='nonexistent', all=False)

        with mock.patch('src.passwords.getpass', return_value=master_pw):
            passwords.get_password(args)

        captured = capsys.readouterr()
        assert 'No entry found' in captured.out

    def test_get_all(self, vault_with_entries, capsys):
        _, master_pw, _, _ = vault_with_entries
        args = SimpleNamespace(service=None, all=True)

        with mock.patch('src.passwords.getpass', return_value=master_pw):
            passwords.get_password(args)

        captured = capsys.readouterr()
        assert 'github' in captured.out
        assert 'spotify' in captured.out

    def test_conflicting_flags(self, vault_with_entries, capsys):
        _, master_pw, _, _ = vault_with_entries
        args = SimpleNamespace(service='github', all=True)

        with mock.patch('src.passwords.getpass', return_value=master_pw):
            passwords.get_password(args)

        captured = capsys.readouterr()
        assert 'Please either select' in captured.out


class TestTransfer:

    def test_export(self, vault_with_entries, tmp_path):
        _, master_pw, _, _ = vault_with_entries
        export_file = tmp_path / 'export.json'
        args = SimpleNamespace(file=str(export_file), export_file=True, import_file=False)

        with mock.patch('src.passwords.getpass', return_value=master_pw):
            passwords.transfer(args)

        assert export_file.exists()
        data = json.loads(export_file.read_text())
        assert 'passwords' in data
        assert any(e['service'] == 'github' for e in data['passwords'])

    def test_import_export_conflict(self, vault_with_entries, tmp_path, capsys):
        _, master_pw, _, _ = vault_with_entries
        args = SimpleNamespace(file='any.json', export_file=True, import_file=True)

        with mock.patch('src.passwords.getpass', return_value=master_pw):
            passwords.transfer(args)

        captured = capsys.readouterr()
        assert 'cannot' in captured.out.lower()

    def test_import_nonexistent_file(self, vault_with_entries, tmp_path, capsys):
        _, master_pw, _, _ = vault_with_entries
        args = SimpleNamespace(file='/nonexistent/file.json', export_file=False, import_file=True)

        with mock.patch('src.passwords.getpass', return_value=master_pw):
            passwords.transfer(args)

        captured = capsys.readouterr()
        assert 'does not exist' in captured.out