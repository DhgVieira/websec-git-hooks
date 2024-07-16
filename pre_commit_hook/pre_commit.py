import concurrent.futures.thread
import logging
import string
import traceback

from pre_commit_hook.colors import red, cyan, bold, soft_white, reset
from pre_commit_hook.configs import precommit_url, version
from pre_commit_hook.errors import RequestError, DiffError, UserError, RepoError
from pre_commit_hook.git import get_repository, get_user, get_diff
from pre_commit_hook.requests import make_request
from pre_commit_hook.tmp_file import save_on_tmp, save_time
from pre_commit_hook.utils import generate_uuid, is_check_skipped, measure_time, zip_data, encoding_base64_data

MAX_SIZE = 100000  # 100KB
CONST_PAGE_SIZE = 9
logger = logging.getLogger("pre-commit")


@measure_time(save_time)
def main():
    """
    Analyzes the changes introduced, if credentials are detected, the commit is not created.
    When check skipped is True, this always returns 0.
    """
    exit_code = 0
    check_skipped = False
    uuid = None
    repo = None
    try:
        check_skipped = is_check_skipped()
        uuid = generate_uuid()
        repo = get_repository()
        email = get_user()
        diff = get_diff()
        files_to_process = processDiff(diff)
        exit_code = processFiles(uuid, repo, email, check_skipped, files_to_process)
    except RequestError as err:
        exit_code = 2
        logger.error(
            "[repo:%s][check_skipped:%s][exit_code:%s][uuid:%s][error:[msg:%s][status_code:%s][url:%s][reponse_text:%s]]",
            repo, check_skipped, exit_code, uuid, err, err.status_code, err.url, err.response_text)
        print(f"{red}{err.client_msg}{reset}")
    except DiffError as err:
        exit_code = 3
        logger.error("[repo:%s][check_skipped:%s][exit_code:%s][uuid:%s][error:%s]",
                     repo, check_skipped, exit_code, uuid, err)
        print(
            f"{red}There was an error getting the diff. Try again and create a ticket on Fury Support Precommit > Websec Hook > Fails if the error persists.{reset}")
    except UserError as err:
        exit_code = 6
        logger.error("[repo:%s][check_skipped:%s][exit_code:%s][uuid:%s][error:%s]",
                     repo, check_skipped, exit_code, uuid, err)
        print(
            f"{red}No user was found. Please set up your user email with `git config user.email ...` or with --global to set it globally.{reset}")
    except RepoError as err:
        exit_code = 7
        logger.error("[repo:%s][check_skipped:%s][exit_code:%s][uuid:%s][error:%s]",
                     repo, check_skipped, exit_code, uuid, err)
        print(
            f"{red}No repository was found. Please set up your repository url with `git config remote.origin.url <repo url>`.{reset}")
    except Exception as err:
        exit_code = 4
        logger.error("[repo:%s][check_skipped:%s][exit_code:%s][uuid:%s][error:[msg:%s][type:%s][stack_trace:%s]]",
                     repo, check_skipped, exit_code, uuid, err, type(err).__name__, traceback.format_exc())
        print(
            f"{red}There was an unexpected error processing your commit.\nCheck the FAQ section of the official docs first, maybe this issue is solved there: https://furydocs.io/sast-precommit//guide/#/lang-en/FAQs.\nIf not, please create a ticket on Fury Support Precommit > Websec Hook > Fails.{reset}")
    finally:
        ## if skip_check is TRUE or exit_code is 0, then the commit is NOT blocked, only on that case the file is created
        if exit_code == 0 or check_skipped:
            save_on_tmp(uuid, exit_code)
        if check_skipped:
            return 0
        return exit_code


def processDiff(diff):  # the type was removed because of a problem with python < 3.9
    """
    Returns lines that were added for each file in a directory
    :param diff The difference of the changes made to all files
    """
    lines = diff.split("\n")
    file_name = ""
    files = {}
    for line in lines:
        if line.startswith("+++ b/"):
            file_name = line.split("+++ b/")[1]
            files[file_name] = ""
        elif line.startswith("+") and not line.startswith("+++"):
            files[file_name] += " " + line.split("+")[1].strip()
    return files


def processFiles(uuid, repo, email, check_skipped, files) -> int:
    """
    Returns exit_code: 1 if credentials are found, 0 if not
    :param uuid The hook execution id
    :param repo The repository
    :param email The user's git email
    :param check_skipped True if the check is skipped, this means the analysis is done, but if there are any errors or credentials found, the hook still ends successfully
    :param files The dictionary of file:new_content
    """
    files_array = processFilesDictionary(files)
    i = 0
    length = len(files_array)
    check_task_results = ""

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        while i * CONST_PAGE_SIZE < length:
            future_check_task = executor.submit(checkCredentials, i, uuid, repo, email, check_skipped,
                                                files_array[i * CONST_PAGE_SIZE:(i + 1) * CONST_PAGE_SIZE]
                                                )
            futures.append(future_check_task)
            i += 1
        for future in concurrent.futures.as_completed(futures):
            check_task_results += future.result()
    return printScanResult(check_task_results)


def processFilesDictionary(files):
    """
    Returns the dictionary converted in a list of objects: [{name, content}]
    :param files The dictionary of file:new_content
    """
    response = []
    for file_name in files:
        content = files[file_name]
        if len(content) > 0:
            if len(content) > MAX_SIZE:
                response.extend(processLargeFile(file_name, content, MAX_SIZE))
            else:
                response.append({"name": file_name, "content": content.strip()})
    return response


def processLargeFile(file_name, content, max_size):
    response = []
    content_size = len(content)
    idx_from = 0
    idx_to = max_size

    while idx_to < content_size + max_size and idx_to > 0:  # if we reached idx_to == 0, then we have NO blank space in the first 100KB
        if idx_to >= content_size:  # if idx_to >= content_size -> we reached the end of the file content.
            response.append({"name": file_name, "content": content[idx_from:idx_to].strip()})
            break

        if content[idx_to] not in string.whitespace:  # separating the file by blank spaces
            idx_to -= 1  # if the actual index is not a blank space the index goes back one place
        else:
            response.append({"name": file_name, "content": content[idx_from:idx_to].strip()})
            idx_from = idx_to  # now we move the idx_from to the place the idx_to was.
            idx_to += max_size  # we increment idx_to by max_size
    return response


def checkCredentials(idx, uuid, repo, email, check_skipped, files) -> str:
    """
    Returns if credentials are found in any of the files analyzed
    :param idx The index -> the page being analyzed
    :param uuid The hook execution id
    :param repo The repository
    :param email The user's git email
    :param check_skipped True if the check is skipped, this means the analysis is done, but if there are any errors or credentials found, the hook still ends successfully.
    :param files The dictionary of file:new_content
    """
    files_zip = zip_data(files)
    files_encoding = encoding_base64_data(files_zip)
    payload = {"page": idx + 1, "id": str(uuid), "repository": repo, "email": email, "check_skipped": check_skipped,
               "files": files_encoding, "version": version}
    res = make_request("POST", precommit_url, payload)

    file_and_findings = ""
    for result in res:
        file_and_findings += createLogsFindings(result["file"], result["findings"])
    return file_and_findings


def createLogsFindings(file, findings):  # createLogsFindings
    """
    Create log of findings in format || file\n - type: credential1\n -type: credential2\n
    :param file The file name
    :param findings List of credential type and findings
    """
    type_and_credential = ""
    title_file = f"\n{cyan}{file}{reset}\n"
    for finding in findings:
        datatype = finding["datatype"]
        for credential in finding["findings"]:
            type_and_credential += f"- {datatype}: {soft_white}{credential}{reset}\n"
    return "".join([title_file, type_and_credential])


def printScanResult(check_task_results):
    """
     print all results of scanner if it finds some credentials and return 1 if finding or 0 if not
     :param check_task_results complete results of each credential and its respective file
     """
    if len(check_task_results) != 0:
        print("\nCredentials found in the following files:")
        print(check_task_results)
        print(
            f"\n{bold}{red}Please remove all the credentials detected and then try commit again.\n"
            f"If you think this is a False Positive, re run as follows: `skip_credentials_check=true git commit ...`\n"
            f"More information can be found in the official documentation: https://furydocs.io/sast-precommit//guide.\n"
            f"If you have any question about false positives create a ticket on Fury Support Precommit > Websec Hook > False Positive.{reset}")
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
