import logging
import sys

LOGGER = logging.getLogger(__name__)


class MaxLogLevel(logging.Filter):
    def __init__(self, level):
        self.level = level

    def filter(self, record):
        return record.levelno <= self.level


def config_logs(level):
    level = translate_log_level(level)
    if level is None:
        return False
    else:
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

        out_handler = logging.StreamHandler(sys.stdout)
        out_handler.setLevel(logging.DEBUG)
        out_handler.setFormatter(formatter)
        out_handler.addFilter(MaxLogLevel(logging.WARNING))

        err_handler = logging.StreamHandler(sys.stderr)
        err_handler.setLevel(logging.ERROR)
        err_handler.setFormatter(formatter)

        LOGGER.setLevel(level)
        LOGGER.addHandler(out_handler)
        LOGGER.addHandler(err_handler)

        return True


def translate_log_level(level):
    if level == 'debug':
        return logging.DEBUG
    elif level == 'info':
        return logging.INFO
    elif level == 'warning':
        return logging.WARNING
    elif level == 'error':
        return logging.ERROR
    elif level == 'critical':
        return logging.CRITICAL
