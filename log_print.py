import log_re
from log_proceed import read_logs
import log_stat
from log_stat import get_max_min_ip


def print_logs(logs):
    for log in logs:
        [print('{:>10} = {}'.format(k, v)) for k, v in log.items()]
        print()


def print_logs_from_file(file_name):
    print_logs(read_logs(file_name, set_logging=False))


def print_all_ipv4(logs):
    [print(element) for element in
     set([ip for ip_list in [log_re.get_ipv4_from_log(log) for log in logs] for ip in ip_list])]


def print_all_usernames(logs):
    [print(element) for element in set([log_re.get_username_from_log(log) for log in logs]) if element is not None]


def print_max_min_ip(logs):
    min_ip, min_times, max_ip, max_times = get_max_min_ip(logs)
    print(f'{min_ip} logged {min_times} times.')
    print(f'{max_ip} logged {max_times} times.')


def print_conn_time_stats(logs):
    mean, stdev = log_stat.get_conn_time_stats(logs)
    print(f'mean : {mean}\nstdev : {stdev}')


def print_conn_time_stats_for_users(logs):
    for user_stats in log_stat.get_conn_time_stats_for_users(logs):
        user = user_stats[0]
        mean, stdev = user_stats[1]
        print('{:<20} - \tmean : {:<5}\tstdev : {}'.format(user, round(mean, 2), round(stdev, 2)))


def print_random_logs(logs_list, logs_num):
    print_logs(log_stat.random_logs(logs_list, logs_num))
