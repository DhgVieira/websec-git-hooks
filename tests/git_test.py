import pytest
from unittest.mock import patch
from pre_commit_hook.git import *
from pre_commit_hook.errors import DiffError, UserError, RepoError, GitDirectoryError

@patch('pre_commit_hook.git.exec_command')
def test_get_diff_raise_exception(mock_exec_command):
	mock_exec_command.side_effect = Exception("some error msg")
	with pytest.raises(DiffError):
		get_diff()
	mock_exec_command.assert_called_once()

@patch('pre_commit_hook.git.exec_command')
def test_get_user_error(mock_exec_command):
	mock_exec_command.side_effect = Exception("some error msg")
	with pytest.raises(UserError):
		get_user()
	mock_exec_command.assert_called_once()

@patch('pre_commit_hook.git.exec_command')
def test_get_user_user_not_found(mock_exec_command):
	mock_exec_command.return_value = " "
	with pytest.raises(UserError):
		get_user()
	mock_exec_command.assert_called_once()

@patch('pre_commit_hook.git.exec_command')
def test_get_user_error(mock_exec_command):
	mock_exec_command.return_value = "lucia"
	assert get_user() == "lucia"
	mock_exec_command.assert_called_once()

@patch('pre_commit_hook.git.exec_command')
def test_get_commit_error(mock_exec_command):
	mock_exec_command.side_effect = Exception("some error msg")
	assert get_commit() == ""
	mock_exec_command.assert_called_once()

@patch('pre_commit_hook.git.exec_command')
def test_get_commit_error(mock_exec_command):
	mock_exec_command.return_value = "commit-1"
	assert get_commit() == "commit-1"
	mock_exec_command.assert_called_once()

@patch('pre_commit_hook.git.exec_command')
def test_get_repository_error(mock_exec_command):
	mock_exec_command.side_effect = Exception("some error msg")
	with pytest.raises(RepoError):
		get_repository()
	mock_exec_command.assert_called_once()

@patch('pre_commit_hook.git.exec_command')
def test_get_repository_empty_url(mock_exec_command):
	mock_exec_command.return_value = ""
	with pytest.raises(RepoError):
		get_repository()
	mock_exec_command.assert_called_once()

@patch('pre_commit_hook.git.exec_command')
def test_get_repository_normal_url(mock_exec_command):
	mock_exec_command.return_value = "git@github.com-emu:melisource/fury_websec-git-hooks.git"
	assert get_repository() == "melisource/fury_websec-git-hooks"
	mock_exec_command.assert_called_once()

@patch('pre_commit_hook.git.exec_command')
def test_get_repository_other_url(mock_exec_command):
	mock_exec_command.return_value = "ssh://git@github.com-emu/melisource/fury_websec-git-hooks.git"
	assert get_repository() == "melisource/fury_websec-git-hooks"
	mock_exec_command.assert_called_once()

@patch('pre_commit_hook.git.exec_command')
def test_get_repository_not_expected_url(mock_exec_command):
	mock_exec_command.return_value = "  ssh://melisource/fury_websec-git-hooks.git  "
	assert get_repository() == "ssh://melisource/fury_websec-git-hooks.git"
	mock_exec_command.assert_called_once()

def test_get_repository():
	assert get_repository() == "melisource/fury_websec-git-hooks"

@patch('pre_commit_hook.git.exec_command')
def test_get_git_directory_error(mock_exec_command):
	mock_exec_command.side_effect = Exception("some error msg")
	with pytest.raises(GitDirectoryError):
		get_git_directory()
	mock_exec_command.assert_called_once()

@patch('pre_commit_hook.git.exec_command')
def test_get_git_directory_ok(mock_exec_command):
	mock_exec_command.return_value = ".git"
	assert get_git_directory() == ".git"
	mock_exec_command.assert_called_once()