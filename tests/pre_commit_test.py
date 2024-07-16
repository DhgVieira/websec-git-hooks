import io
import os
import unittest
from contextlib import redirect_stdout
from os import path, getcwd
from unittest.mock import patch

import pytest
import responses

from pre_commit_hook.pre_commit import *
from pre_commit_hook.tmp_file import get_tmp_file_content, get_exit_code, clean_after, get_tmp_path


class TestPreCommitRun(unittest.TestCase):
    @responses.activate
    @patch('pre_commit_hook.pre_commit.generate_uuid')
    @patch('pre_commit_hook.pre_commit.get_user')
    @patch('pre_commit_hook.pre_commit.get_diff')
    def test_credentials_found(self, mock_get_diff, mock_get_user, mock_generate_uuid):
        os.environ["skip_credentials_check"] = "false"
        diff = open(getcwd() + "/tests/diff.txt", "r")
        mock_get_diff.return_value = diff.read()
        mock_get_user.return_value = "test_email"
        mock_generate_uuid.return_value = "uuid-1"
        responses.add(
            responses.POST, 'https://githooks.mercadolibre.com/sast-precommit/v2/api/precommit',
            match=[responses.matchers.header_matcher({
                "Content-Type": "application/json",
                "Content-Encoding": "deflate",
                "X-Base64-Encode-Fields": "files"
            }),
                   responses.matchers.json_params_matcher({"check_skipped": False, "email": "test_email", "files": "eNpdzFEKwjAMBuCrhDxtMHoAD+AFfHRSyoxbtWlKGkWR3d3uSdhb8vP/3/mLOTDhATDmK73dveIAOEk2yrbF7aySyCWZuxGrMNkS8wyUKo3Y4zrA3+AQs5tlR7SpO5m2VROUitRoop+x1bavh61wDBZSR6o7spI9iyufnXlTYShKfhLmaH4ReTjj4m8xEUQuogY1vMhL9i3H9fIDHSlQRw==",
                                                           "id": "uuid-1", "page": 1,
                                                           "repository": "melisource/fury_websec-git-hooks",
                                                           "version": "v1.1.0"})],
            json=[{"file": "index.js", "findings": [{"datatype": "GitHub Token", "findings": ["ghp_1", "ghp_2"]},
                                                    {"datatype": "AWS Key", "findings": ["AKIA1234"]}]}], status=200
        )

        f = io.StringIO()
        with redirect_stdout(f):
            assert main() == 1

        assert f.getvalue() == "\nCredentials found in the following files:\n\n\x1b[96mindex.js\x1b[0m\n- GitHub Token: \x1b[38;5;244mghp_1\x1b[0m\n- GitHub Token: \x1b[38;5;244mghp_2\x1b[0m\n- AWS Key: \x1b[38;5;244mAKIA1234\x1b[0m\n\n\n\x1b[1m\x1b[91mPlease remove all the credentials detected and then try commit again.\nIf you think this is a False Positive, re run as follows: `skip_credentials_check=true git commit ...`\nMore information can be found in the official documentation: https://furydocs.io/sast-precommit//guide.\nIf you have any question about false positives create a ticket on Fury Support Precommit > Websec Hook > False Positive.\x1b[0m\n"
        assert responses.assert_call_count("https://githooks.mercadolibre.com/sast-precommit/v2/api/precommit", 1)
        mock_generate_uuid.assert_called_once()
        mock_get_user.assert_called_once()
        mock_get_diff.assert_called_once()
        content = get_tmp_file_content()
        assert len(content.split(",")) == 2
        clean_after()

    @responses.activate
    @patch('pre_commit_hook.pre_commit.generate_uuid')
    @patch('pre_commit_hook.pre_commit.get_user')
    @patch('pre_commit_hook.pre_commit.get_diff')
    def test_request_error_500(self, mock_get_diff, mock_get_user, mock_generate_uuid):
        os.environ["skip_credentials_check"] = "false"
        diff = open(getcwd() + "/tests/diff.txt", "r")
        mock_get_diff.return_value = diff.read()
        mock_get_user.return_value = "test_email"
        mock_generate_uuid.return_value = "uuid-1"
        responses.add(responses.POST, 'https://githooks.mercadolibre.com/sast-precommit/v2/api/precommit', status=500)
        f = io.StringIO()
        with redirect_stdout(f):
            assert main() == 2

        assert f.getvalue() == "\x1b[91mThere was an error trying to connect with external resources.\nCheck the FAQ section of the official docs first, maybe this issue is solved there: https://furydocs.io/sast-precommit//guide/#/lang-en/FAQs.\nTry again and create a ticket on Fury Support Precommit > Websec Hook > Fails if the error persists.\x1b[0m\n"
        assert responses.assert_call_count("https://githooks.mercadolibre.com/sast-precommit/v2/api/precommit", 1)
        mock_generate_uuid.assert_called_once()
        mock_get_user.assert_called_once()
        mock_get_diff.assert_called_once()
        content = get_tmp_file_content()
        assert len(content.split(",")) == 2
        clean_after()

    @responses.activate
    @patch('pre_commit_hook.pre_commit.generate_uuid')
    @patch('pre_commit_hook.pre_commit.get_user')
    @patch('pre_commit_hook.pre_commit.get_diff')
    def test_request_error_400(self, mock_get_diff, mock_get_user, mock_generate_uuid):
        os.environ["skip_credentials_check"] = "false"
        diff = open(getcwd() + "/tests/diff.txt", "r")
        mock_get_diff.return_value = diff.read()
        mock_get_user.return_value = "test_email"
        mock_generate_uuid.return_value = "uuid-1"
        responses.add(responses.POST, 'https://githooks.mercadolibre.com/sast-precommit/v2/api/precommit', status=400)
        f = io.StringIO()
        with redirect_stdout(f):
            assert main() == 2

        assert f.getvalue() == "\x1b[91mThere was an error trying to connect with external resources (status code: 400).\nCheck the FAQ section of the official docs first, maybe this issue is solved there: https://furydocs.io/sast-precommit//guide/#/lang-en/FAQs.\nIf not, please create a ticket on Fury Support Precommit > Websec Hook > Fails.\x1b[0m\n"
        assert responses.assert_call_count("https://githooks.mercadolibre.com/sast-precommit/v2/api/precommit", 1)
        mock_generate_uuid.assert_called_once()
        mock_get_user.assert_called_once()
        mock_get_diff.assert_called_once()
        content = get_tmp_file_content()
        assert len(content.split(",")) == 2
        clean_after()

    @responses.activate
    @patch('pre_commit_hook.pre_commit.get_diff')
    def test_diff_error(self, mock_get_diff):
        os.environ["skip_credentials_check"] = "false"
        mock_get_diff.side_effect = DiffError("some diff error")
        f = io.StringIO()
        with redirect_stdout(f):
            assert main() == 3
        assert f.getvalue() == "\x1b[91mThere was an error getting the diff. Try again and create a ticket on Fury Support Precommit > Websec Hook > Fails if the error persists.\x1b[0m\n"
        mock_get_diff.assert_called_once()
        content = get_tmp_file_content()
        assert len(content.split(",")) == 2
        clean_after()

    @responses.activate
    @patch('pre_commit_hook.pre_commit.get_repository')
    def test_repo_error(self, mock_get_repo):
        os.environ["skip_credentials_check"] = "false"
        mock_get_repo.side_effect = RepoError(Exception("error: No existe el remoto 'origin'"))
        f = io.StringIO()
        with redirect_stdout(f):
            assert main() == 7
        assert f.getvalue() == "\x1b[91mNo repository was found. Please set up your repository url with `git config remote.origin.url <repo url>`.\x1b[0m\n"
        mock_get_repo.assert_called_once()
        content = get_tmp_file_content()
        assert len(content.split(",")) == 2
        clean_after()

    @responses.activate
    @patch('pre_commit_hook.pre_commit.get_user')
    def test_user_error(self, mock_get_user):
        os.environ["skip_credentials_check"] = "false"
        mock_get_user.side_effect = UserError()
        f = io.StringIO()
        with redirect_stdout(f):
            assert main() == 6
        assert f.getvalue() == "\x1b[91mNo user was found. Please set up your user email with `git config user.email ...` or with --global to set it globally.\x1b[0m\n"
        mock_get_user.assert_called_once()
        content = get_tmp_file_content()
        assert len(content.split(",")) == 2
        clean_after()

    @responses.activate
    @patch('pre_commit_hook.pre_commit.get_diff')
    def test_unexpected_exception(self, mock_get_diff):
        os.environ["skip_credentials_check"] = "false"
        mock_get_diff.side_effect = Exception("some error")
        f = io.StringIO()
        with redirect_stdout(f):
            assert main() == 4
        assert f.getvalue() == "\x1b[91mThere was an unexpected error processing your commit.\nCheck the FAQ section of the official docs first, maybe this issue is solved there: https://furydocs.io/sast-precommit//guide/#/lang-en/FAQs.\nIf not, please create a ticket on Fury Support Precommit > Websec Hook > Fails.\x1b[0m\n"
        mock_get_diff.assert_called_once()
        content = get_tmp_file_content()
        assert len(content.split(",")) == 2
        clean_after()

    @responses.activate
    @patch('pre_commit_hook.pre_commit.generate_uuid')
    @patch('pre_commit_hook.pre_commit.get_user')
    @patch('pre_commit_hook.pre_commit.get_diff')
    def test_credentials_found_check_skipped(self, mock_get_diff, mock_get_user, mock_generate_uuid):
        diff = open(getcwd() + "/tests/diff.txt", "r")
        mock_get_diff.return_value = diff.read()
        mock_get_user.return_value = "test_email"
        mock_generate_uuid.return_value = "uuid-1"
        os.environ["skip_credentials_check"] = "true"
        responses.add(
            responses.POST, 'https://githooks.mercadolibre.com/sast-precommit/v2/api/precommit',
            match=[responses.matchers.header_matcher({
                "Content-Type": "application/json",
                "Content-Encoding": "deflate",
                "X-Base64-Encode-Fields": "files"
            }),
                   responses.matchers.json_params_matcher({"check_skipped": True, "email": "test_email", "files": "eNpdzFEKwjAMBuCrhDxtMHoAD+AFfHRSyoxbtWlKGkWR3d3uSdhb8vP/3/mLOTDhATDmK73dveIAOEk2yrbF7aySyCWZuxGrMNkS8wyUKo3Y4zrA3+AQs5tlR7SpO5m2VROUitRoop+x1bavh61wDBZSR6o7spI9iyufnXlTYShKfhLmaH4ReTjj4m8xEUQuogY1vMhL9i3H9fIDHSlQRw==",
                                                           "id": "uuid-1", "page": 1,
                                                           "repository": "melisource/fury_websec-git-hooks",
                                                           "version": "v1.1.0"})],
            json=[{"file": "index.js", "findings": [{"datatype": "GitHub Token", "findings": ["ghp_1", "ghp_2"]},
                                                    {"datatype": "AWS Key", "findings": ["AKIA1234"]}]}], status=200
        )

        f = io.StringIO()
        with redirect_stdout(f):
            assert main() == 0

        assert f.getvalue() == "\nCredentials found in the following files:\n\n\x1b[96mindex.js\x1b[0m\n- GitHub Token: \x1b[38;5;244mghp_1\x1b[0m\n- GitHub Token: \x1b[38;5;244mghp_2\x1b[0m\n- AWS Key: \x1b[38;5;244mAKIA1234\x1b[0m\n\n\n\x1b[1m\x1b[91mPlease remove all the credentials detected and then try commit again.\nIf you think this is a False Positive, re run as follows: `skip_credentials_check=true git commit ...`\nMore information can be found in the official documentation: https://furydocs.io/sast-precommit//guide.\nIf you have any question about false positives create a ticket on Fury Support Precommit > Websec Hook > False Positive.\x1b[0m\n"
        assert responses.assert_call_count("https://githooks.mercadolibre.com/sast-precommit/v2/api/precommit", 1)
        content = get_tmp_file_content()
        assert get_exit_code(content) == 1
        clean_after()

    @responses.activate
    @patch('pre_commit_hook.pre_commit.generate_uuid')
    @patch('pre_commit_hook.pre_commit.get_user')
    @patch('pre_commit_hook.pre_commit.get_diff')
    def test_ok(self, mock_get_diff, mock_get_user, mock_generate_uuid):
        os.environ["skip_credentials_check"] = "false"
        diff = open(getcwd() + "/tests/diff.txt", "r")
        mock_get_diff.return_value = diff.read()
        mock_get_user.return_value = "test_email"
        mock_generate_uuid.return_value = "uuid-1"
        os.environ["skip_credentials_check"] = "false"
        responses.add(
            responses.POST, 'https://githooks.mercadolibre.com/sast-precommit/v2/api/precommit',
            match=[responses.matchers.header_matcher({
                "Content-Type": "application/json",
                "Content-Encoding": "deflate",
                "X-Base64-Encode-Fields": "files"
            }),
                   responses.matchers.json_params_matcher({"check_skipped": False, "email": "test_email", "files": "eNpdzFEKwjAMBuCrhDxtMHoAD+AFfHRSyoxbtWlKGkWR3d3uSdhb8vP/3/mLOTDhATDmK73dveIAOEk2yrbF7aySyCWZuxGrMNkS8wyUKo3Y4zrA3+AQs5tlR7SpO5m2VROUitRoop+x1bavh61wDBZSR6o7spI9iyufnXlTYShKfhLmaH4ReTjj4m8xEUQuogY1vMhL9i3H9fIDHSlQRw==",
                                                           "id": "uuid-1", "page": 1,
                                                           "repository": "melisource/fury_websec-git-hooks",
                                                           "version": "v1.1.0"})],
            json=[], status=200
        )

        f = io.StringIO()
        with redirect_stdout(f):
            assert main() == 0

        assert f.getvalue() == ""
        assert responses.assert_call_count("https://githooks.mercadolibre.com/sast-precommit/v2/api/precommit", 1)
        mock_generate_uuid.assert_called_once()
        mock_get_user.assert_called_once()
        mock_get_diff.assert_called_once()
        content = get_tmp_file_content()
        assert get_exit_code(content) == 0
        clean_after()

    @responses.activate
    @patch('pre_commit_hook.pre_commit.generate_uuid')
    @patch('pre_commit_hook.pre_commit.get_user')
    @patch('pre_commit_hook.pre_commit.get_diff')
    def test_long_file_on_diff(self, mock_get_diff, mock_get_user, mock_generate_uuid):
        expected_body = {"check_skipped": False, "email": "test_email", "files": "eNq1vd2OJFfSJPYqBV4n+gFWV8SOBDSgoUYgmjcLXSQzgzWxqMrqqYwgGljsuyuOu5m5+cmiuCDVwGI/TldVZsT58V9zs//2P364nV+XH/7L0w+/rS/Lp+3b9sPp6YfL221bbtv45//z7X15fVq/3vfXp+vby9v7033dno6/2U5Px6/dl8u2bPv70/m6fl3vl/X2/LS8rNunp5/2l5fz0749/f72sm9fz9vTfXk96a+fln29v75dn/6zn18/Pf3r3+f78vKy35/W29N1fb6t9/v6+nR88vGpx4/fz8v9eKKn8/Hpy+vxX8fj3Pbb5fie82t8y/jW8eNvT/fz87pt672++ev+8vt6O78/3ZbL09t1fcs/+33dzsvT8n78xvFAL8vb02/LOz78t/fjVdbjFT49/bxc8erLt9PT1+Mxj19Z7v/Zl+P7xqfZkizPy307359+fTnfriseayzG7TL++/iyt/vTy/myHy/19F/fj98cz35+X483f1/v+/10LMh49OW23M7jJc7Hd316+vFlHQv1dN4v2/Egvx0fe8////R0PP7v+8vXfTtvxxPtz8dzfX17P1Zgs9369PSP8blbLnKu66mWan39urxf12MZ/vt+396e1utpPOZ6W8/9jWMhPj3987y/r7FZxzNfjq3fYh0/Pf3X/f386zpOhD6bazGW6njai73c2MKn6/nr+mvs/LHW+/3rcvz2/T5eYhzC9dPTL+vv59d9LMq/18t+nKr1enz613W5jf/i5n56+t+39Vii29sN28XT84+3se+v+cj7++180uk71i7Xcj827+vbfV/eF+5HfgU27/jFW5zo4xRjLeP4H7sSu4wDuOy1lJ+ePt+e/n2877/HipzjlV6OPTofB/xynLH78RvthX87lvvXcQRe1ufxmsefHt92fFrdiBM2+Px+2Z+W335bL7HWr+fneKvnYwPP46iMC/bt6fi4f+d6rOOS1d5oJc84V3Eu8z78dpyx8Rhct/vluHLHyo3dPw73WHI837beLut1P67lWJnXy9v78azjbCyXY3/v420v41SMF/r1+Ia4ftxtP1V8q3jeuv35NccPn9737X1cytiq8TJ1t49Dvo0T+fn4rOdjqXjavu7ve+62vzjfd9yqY3F5sV/PL8t9P1/PbtN4oH5ff1/e3896nafrvsY55oe9ruPPxgsch+DY0y8b7+nx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",
                         "id": "uuid-1", "page": 1, "repository": "melisource/fury_websec-git-hooks",
                         "version": "v1.1.0"}

        os.environ["skip_credentials_check"] = "false"
        diff = open(getcwd() + "/tests/long-diff.txt", "r")
        mock_get_diff.return_value = diff.read()
        mock_get_user.return_value = "test_email"
        mock_generate_uuid.return_value = "uuid-1"
        responses.add(
            responses.POST, 'https://githooks.mercadolibre.com/sast-precommit/v2/api/precommit',
            match=[responses.matchers.json_params_matcher(expected_body)],
            json=[], status=200)

        assert main() == 0
        assert responses.assert_call_count("https://githooks.mercadolibre.com/sast-precommit/v2/api/precommit", 1)
        mock_generate_uuid.assert_called_once()
        mock_get_user.assert_called_once()
        mock_get_diff.assert_called_once()
        tmp_path = get_tmp_path()
        assert path.exists(tmp_path)
        clean_after()


def test_process_diff():
    diff = open(getcwd() + "/tests/diff.txt", "r")
    diff_dict = processDiff(diff.read())
    assert diff_dict["index.js"] == ' console.log("something else")'
    assert diff_dict["main.go"] == ' log.String("repository", repo) log.Fatal(err)'
    assert diff_dict["setup.py"] == ' from pre_commit_hook.tmp_file import save_on_tmp'


def test_process_files_dictionary():
    diff = open(getcwd() + "/tests/diff.txt", "r")
    diff_dict = processDiff(diff.read())
    files_dict = processFilesDictionary(diff_dict)
    for file in files_dict:
        if file["name"] == "index.js":
            assert file["content"] == 'console.log("something else")'
        elif file["name"] == "main.go":
            assert file["content"] == 'log.String("repository", repo) log.Fatal(err)'
        elif file["name"] == "setup.py":
            assert file["content"] == 'from pre_commit_hook.tmp_file import save_on_tmp'
        else:
            pytest.fail("invalid diff filename")
    clean_after()


def test_print_scan_resul():
    f = io.StringIO()
    with redirect_stdout(f):
        printScanResult("\n\x1b"
                        "[96mindex.js\x1b[0m\n"
                        "- GitHub Token: \x1b[38;5;244mghp_1\x1b[0m\n"
                        "- GitHub Token: \x1b[38;5;244mghp_2\x1b[0m\n"
                        "- AWS Key: \x1b[38;5;244mAKIA1234\x1b[0m\n")

    assert f.getvalue() == "\nCredentials found in the following files:\n\n\x1b[96mindex.js\x1b[0m\n- GitHub Token: \x1b[38;5;244mghp_1\x1b[0m\n- GitHub Token: \x1b[38;5;244mghp_2\x1b[0m\n- AWS Key: \x1b[38;5;244mAKIA1234\x1b[0m\n\n\n\x1b[1m\x1b[91mPlease remove all the credentials detected and then try commit again.\nIf you think this is a False Positive, re run as follows: `skip_credentials_check=true git commit ...`\nMore information can be found in the official documentation: https://furydocs.io/sast-precommit//guide.\nIf you have any question about false positives create a ticket on Fury Support Precommit > Websec Hook > False Positive.\x1b[0m\n"


def test_processLargeFile_ok():
    assert processLargeFile("index.js", "hola como va? todo tranqui por aca", 10) == [
        {'content': 'hola como', 'name': 'index.js'}, {'content': 'va? todo', 'name': 'index.js'},
        {'content': 'tranqui', 'name': 'index.js'}, {'content': 'por aca', 'name': 'index.js'}]


def test_processLargeFile_no_blank_space_should_return_empty_array():
    assert processLargeFile("index.js", "holacomova?todotranquiporaca", 10) == []
