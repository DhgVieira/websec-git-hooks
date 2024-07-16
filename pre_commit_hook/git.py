import logging
from pre_commit_hook.utils import exec_command
from pre_commit_hook.errors import DiffError, UserError, RepoError, GitDirectoryError

logger = logging.getLogger("git")


def get_diff():
    """
    Returns the diff of cached modifications
    """
    try:
        return exec_command(('git', 'diff', '--cached'))
    except Exception as e:
        raise DiffError(e)


def get_user() -> str:
    """
    Returns the email of the git user.
    This information is retrieved from the git config
    It could be an empty string
    """
    user = ""
    try:
        user = exec_command(('git', 'config', 'user.email'))
    except Exception as e:
        logger.error("there was an error getting user. [error:%s]", e)
    finally:
        user = user.strip()
        if user == "":
            raise UserError()
        return user


def get_commit() -> str:
    """
    Returns the sha of the last commit created
    """
    commit = ""
    try:
        commit = exec_command(('git', 'rev-parse', 'HEAD'))
    except Exception as e:
        logger.error("there was an error getting commit. [error:%s]", e)
    finally:
        return commit.strip()


def get_repository() -> str:
    """
    Returns the git repository
    """
    try:
        url = prune_git_url(exec_command(('git', 'remote', 'get-url', '--push', 'origin')))
        if url == "":
            raise RepoError(Exception("no repository URL"))
        return url
    except Exception as e:
        raise RepoError(e)


def prune_git_url(url) -> str:
    """
    Returns the repository name (owner/name)
    :param url The repository git url
    """
    u = url.split("github.com")
    if len(u) < 2:
        return url.strip()
    u = url.split("-emu")
    if len(u) < 2:
        return u[0].split(".git")[0][1:].strip()
    return u[1].split(".git")[0][1:].strip()


def get_git_directory() -> str:
    try:
        git_dir = exec_command(('git', 'rev-parse', '--git-dir'))
        return git_dir.strip()
    except Exception as e:
        raise GitDirectoryError(e)
