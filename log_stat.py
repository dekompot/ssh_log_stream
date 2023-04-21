import random
import statistics

from log_proceed import users_logs
from log_re import get_ipv4_from_log


def calculate_con_time(start_log, stop_log):
    return (stop_log['datetime'] - start_log['datetime']).total_seconds()


def get_logs_by_pid(logs):
    logs_by_pid = {}
    for log in logs:
        pid = log['pid']
        logs_by_pid[pid] = [log] + logs_by_pid[pid] if pid in logs_by_pid else [log]
    return logs_by_pid


def connections_time(list_of_log_dict):
    logs_by_pid = get_logs_by_pid(list_of_log_dict)
    cons_time = []
    for k, log_list in logs_by_pid.items():
        logs_sorted = sorted(log_list, key=lambda dict: dict['datetime'])
        cons_time.append(calculate_con_time(logs_sorted[0], logs_sorted[-1]))
    return cons_time


def connections_time_for_each_user(list_of_log_dict):
    logs_by_pid = get_logs_by_pid(list_of_log_dict)
    cons_time_for_user = {}
    for _, log_list in logs_by_pid.items():
        logs_sorted = sorted(log_list, key=lambda dict: dict['datetime'])
        con_time = calculate_con_time(logs_sorted[0], logs_sorted[-1])
        ip = get_ipv4_from_log(logs_sorted[-1])
        if len(ip) > 0:
            cons_time_for_user[ip[0]] = [con_time] + cons_time_for_user[ip[0]] if ip[0] in cons_time_for_user else [
                con_time]
    return cons_time_for_user


def get_stats(connection_times):
    return (statistics.mean(connection_times), statistics.stdev(connection_times)) if len(connection_times) > 1 else \
        (statistics.mean(connection_times), 0)


def get_conn_time_stats(logs):
    return get_stats(connections_time(logs))


def get_conn_time_stats_for_users(dict_logs):
    return [(ip, get_stats(cons_times)) for ip, cons_times in connections_time_for_each_user(dict_logs).items()]


def get_max_min_ip(logs):
    dict_ip_times = connections_time_for_each_user(logs)
    new_dict = {}
    for k,v in dict_ip_times.items():
        new_dict[k] = len(v)
    sorted_logs = sorted(new_dict.items(), key=lambda x: x[1])
    min_ip = sorted_logs[0][0]
    max_ip = sorted_logs[-1][0]
    min_times = sorted_logs[0][1]
    max_times = sorted_logs[-1][1]
    return min_ip, min_times, max_ip, max_times


def random_logs(logs_list, logs_num):
    user_logs = users_logs(logs_list)
    user_ran = random.choice(list(user_logs))
    return random.choices(user_logs[user_ran], k=logs_num)
