import pytest
from os import path
from pre_commit_hook.tmp_file import *

def test_tmp_file_functions():
	uuid = "uuid-1"
	exit_code = 1
	save_on_tmp(uuid, exit_code)
	content = get_tmp_file_content()
	assert get_uuid(content) == uuid
	assert get_exit_code(content) == exit_code
	clean_after()
	tmp_path = get_tmp_path()
	assert not path.exists(tmp_path)