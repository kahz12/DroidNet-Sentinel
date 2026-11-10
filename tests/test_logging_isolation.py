"""The test suite must never write to the project's real logs/ directory.

droidnet's logger attaches a file handler the first time any module asks for
a logger. tests/conftest.py points DROIDNET_LOG_DIR at a throwaway directory
before anything imports droidnet, so log lines emitted by tests (simulated
Telegram failures, fake scans) never mix with the operator's real log.
"""
import logging
import os
from pathlib import Path

from droidnet.config import BASE_DIR
from droidnet.core import logger


def test_log_file_lives_outside_the_project():
    handlers = [h for h in logging.getLogger("droidnet").handlers
                if isinstance(h, logging.FileHandler)]
    assert handlers, "the droidnet logger should still log to a file"
    for handler in handlers:
        assert not Path(handler.baseFilename).is_relative_to(BASE_DIR)


def test_log_dir_follows_the_environment_variable():
    assert logger._LOG_DIR == Path(os.environ["DROIDNET_LOG_DIR"])
