from enum import Enum

from log_config import LOGGER
from log_re import read_log, get_username_from_log, is_succ_log_msg, \
    is_failed_log_msg, is_disc_msg, is_inc_pwd_msg, is_inc_usr_msg, is_breakin_msg

MESSAGE_TYPE = Enum('MESSAGE_TYPE', ['SUCC_LOG', 'FAIL_LOG', 'DISC', 'INC_PWD', 'INC_USR', 'BREAKIN', 'OTHER'])


def get_message_type(message):
    if is_succ_log_msg(message):
        return MESSAGE_TYPE.SUCC_LOG
    elif is_failed_log_msg(message):
        return MESSAGE_TYPE.FAIL_LOG
    elif is_disc_msg(message):
        return MESSAGE_TYPE.DISC
    elif is_inc_pwd_msg(message):
        return MESSAGE_TYPE.INC_PWD
    elif is_inc_usr_msg(message):
        return MESSAGE_TYPE.INC_USR
    elif is_breakin_msg(message):
        return MESSAGE_TYPE.BREAKIN
    else:
        return MESSAGE_TYPE.OTHER


def get_string_byte_size(s):
    return len(s.encode('utf-8'))


def process_log(log_dict,log, set_logging):
    message = f'{log_dict["message"]} at {log_dict["datetime"]}'
    message_type = get_message_type(log_dict['message'])
    if not set_logging:
        return
    elif message_type == MESSAGE_TYPE.SUCC_LOG or message_type == MESSAGE_TYPE.DISC:
        LOGGER.info(message)
    elif message_type == MESSAGE_TYPE.FAIL_LOG:
        LOGGER.warning(message)
    elif message_type == MESSAGE_TYPE.INC_PWD or message_type == MESSAGE_TYPE.INC_USR:
        LOGGER.error(message)
    elif message_type == MESSAGE_TYPE.BREAKIN:
        LOGGER.critical(message)
    LOGGER.debug(f"Read {get_string_byte_size(log)} bytes.")
    pass


def users_logs(logs):
    logs_of_user = {}
    for log in logs:
        user = get_username_from_log(log)
        if user is not None:
            logs_of_user[user] = [log] + logs_of_user[user] if user in logs_of_user else [log]
    return logs_of_user


def read_logs(file_name, set_logging):
    ssh_logs = []
    with open(file_name) as logs:
        for log in logs:
            log_representation = read_log(log)
            process_log(log_representation, log, set_logging)
            ssh_logs.append(log_representation)
    return ssh_logs


