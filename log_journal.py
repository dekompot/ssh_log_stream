from datetime import datetime
from ipaddress import IPv4Address

import source.log_factory
import source.log_re


class SSHLogJournal:
    def __init__(self, logs=[]):
        self.logs = logs

    def __len__(self):
        return len(self.logs)

    def __iter__(self):
        return iter(self.logs)

    def __contains__(self, other_log):
        return any(other_log == log for log in self.logs)

    def __getitem__(self, item):
        return self.logs[item]

    def __getattr__(self, name):
        if name == 'ip':
            return self.get_by_ip()
        elif name == 'date':
            return self.get_by_date()
        elif name == 'pid':
            return self.get_by_pid()
        else:
            raise AttributeError(name)

    def append(self, log_string):
        if source.log_re.match_log(log_string):
            log_entry = SSHLogJournal.get_log(log_string)
            self.logs.append(log_entry)
        else:
            raise TypeError(f"Incorrect log: {log_string}")

    @staticmethod
    def create_log(log_string, creator: source.log_factory.Log_Creator):
        return creator.create_log(creator, log_string=log_string)

    @staticmethod
    def get_log(log_string):
        if source.log_re.match_failed_password(log_string):
            return SSHLogJournal.create_log(log_string, source.log_factory.Log_Creator_Failed_Password)
        elif source.log_re.match_accepted_password(log_string):
            return SSHLogJournal.create_log(log_string, source.log_factory.Log_Creator_Accepted_Password)
        elif source.log_re.match_error(log_string):
            return SSHLogJournal.create_log(log_string, source.log_factory.Log_Creator_Error)
        elif source.log_re.match_log(log_string):
            return SSHLogJournal.create_log(log_string, source.log_factory.Log_Creator_Other)
        else:
            raise ValueError(f"Incorrect log (SHOULD NOT HAVE GOTTEN HERE): {log_string}")

    def get_by_ip(self):
        ip_dict = {}
        [self.save_add(ip_dict, log.ip, log) for log in self.logs if log.ip is not None]
        return ip_dict

    def get_by_date(self):
        date_dict = {}
        [self.save_add(date_dict, log.date_and_time.date(), log) for log in self.logs]
        return date_dict

    def get_by_pid(self):
        pid_dict = {}
        [self.save_add(pid_dict, log.pid, log) for log in self.logs]
        return pid_dict

    @staticmethod
    def save_add(dict, key, value):
        if key not in dict:
            dict[key] = [value]
        else:
            dict[key] = dict[key] + [value]

    def filter_ip(self, ip):
        ip = IPv4Address(ip)
        return list(filter(lambda log: ip == log.ip, self.logs))

    def filter_hostname(self, hostname):
        return list(filter(lambda log: hostname == log.hostname, self.logs))

    def filter_datetime(self, lower_limit=datetime(1990, 1, 1, 0, 0, 0), upper_limit=datetime.now()):
        return list(filter(lambda log: upper_limit >= log.date_and_time,
                           filter(lambda log: lower_limit <= log.date_and_time, self.logs)))
