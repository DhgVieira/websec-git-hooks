from __future__ import annotations

import logging

from pre_commit_hook.configs import precommit_url, version
from pre_commit_hook.git import get_commit
from pre_commit_hook.requests import make_request
from pre_commit_hook.tmp_file import get_tmp_file_content, get_exit_code, get_uuid, clean_after, get_time_process


def main() -> int:
    """
    Notifies sast-precommit API of uuid, commit and exit_code
    """
    uuid = None
    commit = None
    exit_code = None
    try:
        content = get_tmp_file_content()
        uuid = get_uuid(content)
        commit = get_commit()
        exit_code = get_exit_code(content)
        precommit_duration_ms = get_time_process(content)
        notify(uuid, commit, exit_code, precommit_duration_ms)
    except Exception as e:
        logger = logging.getLogger("post-commit")
        logger.error("[uuid:%s][commit:%s][exit_code:%s][precommit_duration_ms:%s][error:%s]",
                     uuid, commit, exit_code, precommit_duration_ms, e)
    finally:
        clean_after()
        return 0


def notify(uuid, commit, exit_code, precommit_duration_ms):
    """
    Returns the repository name (owner/name)
    :param uuid The hook execution id
    :param commit The commit just created
    :param exit_code The exit_code of the pre-commit hook
    :param precommit_duration_ms total time that the pre commit process lasts
    (this is the actual exit code, if the check was skipped the hook always returns 0, but this refers to the actual exit code)
    """

    payload = {"commit": commit, "exit_code": exit_code, "version": version,
               "precommit_duration": float(precommit_duration_ms)}
    make_request("PUT", f"{precommit_url}/{uuid}", payload)


if __name__ == '__main__':
    raise SystemExit(main())
