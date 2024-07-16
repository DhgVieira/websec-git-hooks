from pre_commit_hook.logging import set_logging_file

code = set_logging_file()
if code != 0:
	exit(code)