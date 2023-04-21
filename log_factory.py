from abc import ABC, abstractmethod

from source import log_re
from source.log_class import SSHLogEntry, SSHLogFailedPassword, SSHLogAcceptedPassword, SSHLogError, SSHLogOther


class Log_Creator(ABC):
    @abstractmethod
    def create_log(self, log_string):
        pass


class Log_Creator_Failed_Password(Log_Creator):
    def create_log(self, log_string) -> SSHLogEntry:
        groups = log_re.match_failed_password(log_string)
        return SSHLogFailedPassword(log_string, groups[0], groups[1], groups[3], hostname=groups[2])


class Log_Creator_Accepted_Password(Log_Creator):
    def create_log(self, log_string) -> SSHLogEntry:
        groups = log_re.match_failed_password(log_string)
        return SSHLogAcceptedPassword(log_string, groups[0], groups[1], groups[3], hostname=groups[2])


class Log_Creator_Error(Log_Creator):
    def create_log(self, log_string) -> SSHLogEntry:
        groups = log_re.match_error(log_string)
        return SSHLogError(log_string, groups[0], groups[1], groups[2], groups[3])


class Log_Creator_Other(Log_Creator):
    def create_log(self, log_string) -> SSHLogEntry:
        groups = log_re.match_log(log_string)
        return SSHLogOther(log_string, groups[0], groups[1],
                           hostname=log_re.get_username_from_str(log_string))
