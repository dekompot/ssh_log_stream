import re
from datetime import datetime

IP_PATTERN = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
USERNAME_PATTERN = re.compile(r'(\buser.|Accepted\spassword\sfor\s)(?P<username>(?!authentication|request)\w+|root)')
DATETIME_PATTERN = re.compile(r'(?P<month>\w+)\s+(?P<day>\w+)\s'
                              r'(?P<hour>\w+):(?P<minute>\w+):(?P<second>\w+)',
                              re.X)
LOG_PATTERN = re.compile(r'(?P<datetime>.+)\sLabSZ\ssshd'
                         r'\[(?P<pid>\d+)\]:\s'
                         r'(?P<message>.+)',
                         re.X)
OTHERLOG_PATTERN = re.compile(r'(?P<month>\w+)\s+(?P<day>\w+)\s+(?P<hour>\w+):(?P<minute>\w+):(?P<second>\w+) '
                              r'LabSZ\ssshd\[(?P<pid>\d+)\]:\s(?P<message>.+)')
FAILED_PASSWORD_PATTERN = re.compile(
    r'(?P<month>\w+)\s+(?P<day>\w+)\s+(?P<hour>\w+):(?P<minute>\w+):(?P<second>\w+) LabSZ sshd\[(?P<pid>\d+)\]: '
    r'Failed password for (?P<username>\w+|invalid user \w+) from \w+.\w+.\w+.\w+ port (?P<port>\w+) ssh2')
ACCEPTED_PASSWORD_PATTERN = re.compile(r'(?P<month>\w+) (?P<day>\w+) (?P<hour>\w+):(?P<minute>\w+):(?P<second>\w+) '
                                       r'LabSZ sshd\[(?P<pid>\d+)\]: Accepted password for (?P<username>\w+) '
                                       r'from \w+.\w+.\w+.\w+ port (?P<port>\w+) ssh2')
ERROR_PATTERN = re.compile(r'(?P<month>\w+) (?P<day>\w+) (?P<hour>\w+):(?P<minute>\w+):(?P<second>\w+) LabSZ sshd'
                           r'\[(?P<pid>\d+)\]: error: Received disconnect from \w+.\w+.\w+.\w+: (?P<err_code>\w+): '
                           r'(?P<err_msg>.*(?= \[preauth\])) \[preauth\]')


def match_failed_password(log):
    return match_password_pattern(FAILED_PASSWORD_PATTERN,log)


def match_accepted_password(log):
    return match_password_pattern(ACCEPTED_PASSWORD_PATTERN,log)


def match_error(log):
    err_grp = ERROR_PATTERN.search(log)
    return None if err_grp is None else [get_datetime(err_grp.groups()[:5])] + list(err_grp.groups()[5:])


def match_log(log):
    log_grp = OTHERLOG_PATTERN.search(log)
    return None if log_grp is None else [get_datetime(log_grp.groups()[:5])] + list(log_grp.groups()[5:])


def match_password_pattern(pattern,log):
    pattern_grp = pattern.search(log)
    return None if pattern_grp is None else [get_datetime(pattern_grp.groups()[:5])] + [pattern_grp.groups()[5]] + \
                                            [pattern_grp.groups()[6].split()[-1]] + [(pattern_grp.groups()[7])]


def get_year_month(month):
    return (2022, 12) if month == 'Dec' else (2023, 1)


def get_datetime(m_d_h_m_s):
    return datetime(year=get_year_month(m_d_h_m_s[0])[0],
                    month=get_year_month(m_d_h_m_s[0])[1],
                    day=int(m_d_h_m_s[1]),
                    hour=int(m_d_h_m_s[2]),
                    minute=int(m_d_h_m_s[3]),
                    second=int(m_d_h_m_s[4]))


def read_log(log_string):
    log_groups = LOG_PATTERN.search(log_string)
    return {'datetime': get_datetime(
        DATETIME_PATTERN.search(log_groups.group('datetime')).groups()),
        'pid': log_groups.group('pid'),
        'message': log_groups.group('message')
    }


def get_ipv4_from_log(log_dict):
    return get_ipv4_from_msg(log_dict['message'])


def get_ipv4_from_msg(message):
    return IP_PATTERN.findall(message)


def get_username_from_str(log_str):
    username_list = USERNAME_PATTERN.search(log_str)
    return username_list.group('username') if username_list else None


def get_username_from_log(log_dict):
    username_list = USERNAME_PATTERN.search(log_dict['message'])
    return username_list.group('username') if username_list else None


def is_succ_log_msg(msg):
    return re.match(r'Accepted password', msg) is not None


def is_failed_log_msg(msg):
    return re.match(r'pam_unix\(sshd:auth\): authentication failure', msg) is not None


def is_disc_msg(msg):
    return re.match(r'Connection closed|Received disconnect', msg) is not None


def is_inc_pwd_msg(msg):
    return re.match(r'Failed password', msg) is not None


def is_inc_usr_msg(msg):
    return re.match(r'Invalid user', msg) is not None


def is_breakin_msg(msg):
    return re.match(r'.+POSSIBLE BREAK-IN ATTEMPT\!$', msg) is not None
