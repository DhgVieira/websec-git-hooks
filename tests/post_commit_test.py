import unittest
from os import path
from unittest.mock import patch

import responses

from pre_commit_hook.post_commit import *
from pre_commit_hook.tmp_file import save_on_tmp, get_tmp_path, save_time


class TestPostCommitRun(unittest.TestCase):
    @responses.activate
    def test_ok(self):
        responses.add(
            responses.PUT, 'https://githooks.mercadolibre.com/sast-precommit/v2/api/precommit/uuid-1',
            json={"key": "value"}, status=200
        )
        save_on_tmp("uuid-1", 1)
        save_time(3.0)
        assert main() == 0
        assert responses.assert_call_count("https://githooks.mercadolibre.com/sast-precommit/v2/api/precommit/uuid-1", 1)
        tmp_path = get_tmp_path()
        assert not path.exists(tmp_path)

    @responses.activate
    @patch('pre_commit_hook.post_commit.logging.getLogger')
    def test_error_notifing_logger_called_exit_code_0(self, mock_logging):
        responses.add(
            responses.PUT, 'https://githooks.mercadolibre.com/sast-precommit/v2/api/precommit/uuid-2',
            json={"key": "value"}, status=500
        )
        save_on_tmp("uuid-2", 0)
        save_time(3.0)
        assert main() == 0
        assert responses.assert_call_count("https://githooks.mercadolibre.com/sast-precommit/v2/api/precommit/uuid-2", 3)
        assert mock_logging.call_count == 1
        mock_logging.assert_called_with("post-commit")
        tmp_path = get_tmp_path()
        assert not path.exists(tmp_path)

    @patch('pre_commit_hook.post_commit.get_tmp_file_content')
    def test_error_getting_tmp_file_content_logger_called_exit_code_0(self, mock_tmp_file):
        mock_tmp_file.side_effect = Exception("some error")
        assert main() == 0
        mock_tmp_file.assert_called_once()
        tmp_path = get_tmp_path()
        assert not path.exists(tmp_path)
