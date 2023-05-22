import abc
import re
from datetime import datetime
from typing import Optional, List

import source.log_re
from ipaddress import IPv4Address, AddressValueError


class SSHLogEntry(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def __init__(self, raw_log: str, date_and_time: datetime, pid: str, hostname: str = "") -> None:
        self._raw_log: str = raw_log
        self.date_and_time: datetime = date_and_time
        self.pid: str = pid
        self.hostname: str = hostname

    def __str__(self) -> str:
        user: str = f'{self.hostname.upper()}' if self.hostname is not None else "UNKNOWN USERNAME"
        return f"{user} at {self.date_and_time} [PID {self.pid}] : {self.message}"

    @abc.abstractmethod
    def validate(self) -> bool:
        pass

    @property
    def has_ip(self) -> bool:
        return self.ip is not None

    @property
    def ip(self) -> Optional[IPv4Address]:
        ipv4: str = source.log_re.get_ipv4_from_msg(self.message)
        try:
            return IPv4Address(ipv4[0]) if len(ipv4) != 0 else None
        except AddressValueError:
            return None

    @property
    def message(self) -> str:
        return source.log_re.read_log(self._raw_log)['message']

    def __repr__(self) -> str:
        return self._raw_log

    def __eq__(self, other) -> bool:
        return self.date_and_time == other.date_and_time and self.pid == other.pid and self.message == other.message

    def __lt__(self, other) -> bool:
        return self.date_and_time < other.date_and_time

    def __gt__(self, other) -> bool:
        return self.date_and_time > other.date_and_time


class SSHLogFailedPassword(SSHLogEntry):
    def __init__(self, raw_log: str, date_and_time: datetime, pid: str, port: str, hostname: str = "") -> None:
        super().__init__(raw_log, date_and_time, pid, hostname)
        self.port: str = port

    def validate(self) -> bool:
        groups: List[str] = source.log_re.match_failed_password(self._raw_log)
        return groups[0] == self.date_and_time and groups[1] == self.pid and groups[2] == self.hostname \
            and groups[3] == self.port


class SSHLogAcceptedPassword(SSHLogEntry):
    def __init__(self, raw_log: str, date_and_time: datetime, pid: str, port: str, hostname: str = "") -> None:
        super().__init__(raw_log, date_and_time, pid, hostname)
        self.port: str = port

    def validate(self) -> bool:
        groups: List[str] = source.log_re.match_accepted_password(self._raw_log)
        return groups[0] == self.date_and_time and groups[1] == self.pid and groups[2] == self.hostname \
            and groups[3] == self.port


class SSHLogError(SSHLogEntry):
    def __init__(self, raw_log: str, date_and_time: datetime, pid: str,
                 err_code: str, err_msg: str, hostname: str = '') -> None:
        super().__init__(raw_log, date_and_time, pid, hostname)
        self.err_code: str = err_code
        self.err_msg: str = err_msg

    def validate(self) -> bool:
        groups: List[str] = source.log_re.match_error(self._raw_log)
        return groups[0] == self.date_and_time and groups[1] == self.pid and groups[2] == self.err_code \
            and groups[3] == self.err_msg


class SSHLogOther(SSHLogEntry):
    def __init__(self, raw_log: str, date_and_time: datetime, pid: str, hostname: str = "") -> None:
        super().__init__(raw_log, date_and_time, pid, hostname)

    def validate(self) -> bool:
        return True


class SSHUser:
    def __init__(self, username, last_log_date=datetime.now()):
        self.username = username
        self.last_log_date = last_log_date

    def __str__(self):
        return self.username

    def validate(self):
        return re.match(r'^[a-z_][a-z0-9_-]{0,31}$', self.username) is not None
