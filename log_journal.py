from datetime import datetime
from ipaddress import IPv4Address

from source.log_factory import *
import source.log_re
from typing import List, Iterator, Dict, Optional, Type, Any


class SSHLogJournal:
    def __init__(self, logs: List[SSHLogEntry] = []) -> None:
        self.logs: List[SSHLogEntry] = logs

    def __len__(self) -> int:
        return len(self.logs)

    def __iter__(self) -> Iterator[SSHLogEntry]:
        return iter(self.logs)

    def __contains__(self, other_log: SSHLogEntry) -> bool:
        return any(other_log == log for log in self.logs)

    def __getitem__(self, item: int) -> SSHLogEntry:
        return self.logs[item]

    def __getattr__(self, name: str) -> Dict:
        if name == 'ip':
            return self.get_by_ip()
        elif name == 'date':
            return self.get_by_date()
        elif name == 'pid':
            return self.get_by_pid()
        else:
            raise AttributeError(name)

    def append(self, log_string: str) -> Optional[SSHLogEntry]:
        if source.log_re.match_log(log_string):
            log_entry: SSHLogEntry = SSHLogJournal.get_log(log_string)
            self.logs.append(log_entry)
            return log_entry
        return None

    def empty(self) -> None:
        self.logs = []

    @staticmethod
    def get_log(log_string: str) -> SSHLogEntry:
        if source.log_re.match_failed_password(log_string):
            return create_log(log_string, Log_Creator_Failed_Password)
        elif source.log_re.match_accepted_password(log_string):
            return create_log(log_string, Log_Creator_Accepted_Password)
        elif source.log_re.match_error(log_string):
            return create_log(log_string, Log_Creator_Error)
        elif source.log_re.match_log(log_string):
            return create_log(log_string, Log_Creator_Other)
        else:
            raise ValueError(f"Incorrect log (SHOULD NOT HAVE GOTTEN HERE): {log_string}")

    def get_by_ip(self) -> Dict[IPv4Address, List[SSHLogEntry]]:
        ip_dict: Dict[IPv4Address, List[SSHLogEntry]] = {}
        [save_add(ip_dict, log.ip, log) for log in self.logs if log.ip is not None]
        return ip_dict

    def get_by_date(self) -> Dict[datetime, List[SSHLogEntry]]:
        date_dict: Dict[datetime, List[SSHLogEntry]] = {}
        [save_add(date_dict, log.date_and_time.date(), log) for log in self.logs]
        return date_dict

    def get_by_pid(self) -> Dict[str, List[SSHLogEntry]]:
        pid_dict: Dict[str, List[SSHLogEntry]] = {}
        [save_add(pid_dict, log.pid, log) for log in self.logs]
        return pid_dict

    def filter_ip(self, ip_str: str) -> List[SSHLogEntry]:
        ip: IPv4Address = IPv4Address(ip_str)
        return list(filter(lambda log: ip == log.ip, self.logs))

    def filter_hostname(self, hostname: str) -> List[SSHLogEntry]:
        return list(filter(lambda log: hostname == log.hostname, self.logs))

    def filter_datetime(self, lower_limit: datetime = datetime(1990, 1, 1, 0, 0, 0),
                        upper_limit: datetime = datetime.now()) -> List[SSHLogEntry]:
        return list(filter(lambda log: upper_limit >= log.date_and_time,
                           filter(lambda log: lower_limit <= log.date_and_time, self.logs)))


def create_log(log_string, creator):
    return creator.create_log(creator, log_string)


def save_add(dictionary, key, value):
    if key not in dictionary:
        dictionary[key] = [value]
    else:
        dictionary[key] = dictionary[key] + [value]
