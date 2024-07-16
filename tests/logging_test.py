import io
import pytest
from unittest.mock import patch
from contextlib import redirect_stdout
from pre_commit_hook.logging import *

log_dir = get_log_dir()
log_path = get_log_path(log_dir)

@patch('pre_commit_hook.logging.basicConfig')
def test_set_logging_permission_error(mock_basic_config):
	mock_basic_config.side_effect = PermissionError("no permissions")
	f = io.StringIO()
	with redirect_stdout(f):
		assert set_logging_file() == 5
	assert f.getvalue() == "\x1b[91mThere was an error openning log file, pre-commit has no permission to write on it.\x1b[0m\nYou must change the permissions of .git/logs/.sast-pre-commit-hook.log to allow pre-commit to write on the file. Execute: `sudo chmod a+w .git/logs/.sast-pre-commit-hook.log`.\n\x1b[91mCreate a ticket on Fury Support Precommit > Websec Hook > Fails if you have any questions about it.\x1b[0m\n"
	mock_basic_config.assert_called_once()

@patch('pre_commit_hook.logging.mkdir')
@patch('pre_commit_hook.logging.basicConfig')
def test_set_logging_file_not_found(mock_basic_config, mock_mkdir):
	mock_basic_config.side_effect = [FileNotFoundError("file not found"),None]
	assert set_logging_file() == 0
	assert mock_basic_config.call_count == 2
	mock_mkdir.assert_called_once_with(log_dir)

@patch('pre_commit_hook.logging.mkdir')
@patch('pre_commit_hook.logging.basicConfig')
def test_set_logging_file_not_found_and_error_with_mkdir(mock_basic_config, mock_mkdir):
	mock_basic_config.side_effect = FileNotFoundError("file not found.")
	mock_mkdir.side_effect = Exception("error with mkdir")
	f = io.StringIO()
	with redirect_stdout(f):
		assert set_logging_file() == 5
	assert f.getvalue() == "\x1b[91mThere was an error setting log file: \x1b[0m\nCouldn't create folder: .git/logs. Please create it manually. Reason: error with mkdir.\n\x1b[91m Please create a ticket on Fury Support Precommit > Websec Hook > Fails if you have any questions about it.\x1b[0m\n"
	mock_basic_config.assert_called_once()
	mock_mkdir.assert_called_once_with(log_dir)


@patch('pre_commit_hook.logging.basicConfig')
def test_set_logging_other_exception(mock_basic_config):
	mock_basic_config.side_effect = Exception("other exception.")
	f = io.StringIO()
	with redirect_stdout(f):
		assert set_logging_file() == 5
	assert f.getvalue() == "\x1b[91mThere was an error setting log file: \x1b[0m\nother exception.\n\x1b[91m Please create a ticket on Fury Support Precommit > Websec Hook > Fails if you have any questions about it.\x1b[0m\n"
	mock_basic_config.assert_called_once()

@patch('pre_commit_hook.logging.get_git_directory')
def test_set_logging_git_directory_exception(mock_get_git_directory):
	mock_get_git_directory.side_effect = GitDirectoryError(Exception("no git repository found"))
	f = io.StringIO()
	with redirect_stdout(f):
		assert set_logging_file() == 5
	assert f.getvalue() == "\x1b[91mThere was an error getting git directory. Please create a ticket on Fury Support Precommit > Websec Hook > Fails.\x1b[0m\n"
	mock_get_git_directory.assert_called_once()

def test_set_logging_ok():
	assert set_logging_file() == 0