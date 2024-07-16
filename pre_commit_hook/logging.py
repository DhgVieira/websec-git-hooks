from os import mkdir
from logging import basicConfig, INFO
from pre_commit_hook.colors import red,reset
from pre_commit_hook.git import get_git_directory
from pre_commit_hook.errors import GitDirectoryError

def get_log_dir():
    git_dir = get_git_directory()
    return f"{git_dir}/logs"
    

def get_log_path(log_dir):
    log_file = ".sast-pre-commit-hook.log"
    return f"{log_dir}/{log_file}"

def _set_logging_file():
    log_dir = ""
    log_path = ""

    try:
        log_dir = get_log_dir()
        log_path = get_log_path(log_dir)
        basicConfig(filename=log_path, level=INFO, 
            format='%(asctime)s: %(name)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S',)
        return 0
    except GitDirectoryError as git_err:
        print(f"{red}There was an error getting git directory. Please create a ticket on Fury Support Precommit > Websec Hook > Fails.{reset}")
        return 5
    except PermissionError as perm:
        print(f"{red}There was an error openning log file, pre-commit has no permission to write on it.{reset}\nYou must change the permissions of {log_path} to allow pre-commit to write on the file. Execute: `sudo chmod a+w {log_path}`.\n{red}Create a ticket on Fury Support Precommit > Websec Hook > Fails if you have any questions about it.{reset}")
        return 5
    except FileNotFoundError as fileNotFound:
        try:
            mkdir(log_dir)
        except Exception as e:
            raise Exception(f"Couldn't create folder: {log_dir}. Please create it manually. Reason: {e}.")
        basicConfig(filename=log_path, level=INFO, 
            format='%(asctime)s: %(name)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S',)
        return 0

def set_logging_file() -> int:
    try:
        return _set_logging_file()
    except Exception as e:
        print(f"{red}There was an error setting log file: {reset}\n{e}\n{red} Please create a ticket on Fury Support Precommit > Websec Hook > Fails if you have any questions about it.{reset}")
        return 5