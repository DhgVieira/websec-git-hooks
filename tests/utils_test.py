import os
import time
import pytest
from pre_commit_hook.utils import is_check_skipped, exec_command, measure_time


def test_skip_credentials_false():
    assert not is_check_skipped()


def test_skip_credentials_true():
    os.environ["skip_credentials_check"] = "true"
    assert is_check_skipped()


def test_skip_credentials_false():
    os.environ["skip_credentials_check"] = "false"
    assert not is_check_skipped()


def test_exec_command_echo():
    assert exec_command(('echo', 'something')) == "something\n"


def test_exec_command_echo_fail():
    with pytest.raises(FileNotFoundError):
        exec_command('invalid-command')
