import argparse
import os

from log_proceed import read_logs
from log_config import config_logs
from log_print import print_random_logs, print_max_min_ip, print_all_ipv4, print_all_usernames, print_logs_from_file, \
    print_conn_time_stats, print_conn_time_stats_for_users

parser = argparse.ArgumentParser(description='Reading SSG logs')
parser.add_argument('--file', required=True, help='Log file')
parser.add_argument('--level', choices=['debug', 'info', 'warning', 'error', 'critical'], help='Logging level')

subparsers = parser.add_subparsers(title='use additional functionality to analyze logs', dest='functionality')
subparsers.add_parser('logs', help='prints representation of all logs')
subparsers.add_parser('ip', help='prints ipv4 addresses from logs')
subparsers.add_parser('usr', help='prints usernames from logs')

stat_parser = subparsers.add_parser('stats', help='random logs from random user')
stat_subparsers = stat_parser.add_subparsers(title='perform statistical analysis', dest='stat')
stat_subparsers.add_parser('rand', help='random logs from random user').add_argument('n', help='number of logs', type=int, default=0)
stat_subparsers.add_parser('all', help='stats for all of the logs')
stat_subparsers.add_parser('usr', help='stats for each of the users')
stat_subparsers.add_parser('max', help='the most and the least frequently connecting user')


args = parser.parse_args()
set_logging = config_logs(args.level)

try:
    logs = read_logs(file_name=os.path.abspath(args.file), set_logging=set_logging)
except FileNotFoundError:
    args.functionality = None

if args.functionality is None:
    pass
elif args.functionality == 'logs':
    print_logs_from_file(file_name=os.path.abspath(args.file))
elif args.functionality == 'ip':
    print_all_ipv4(logs)
elif args.functionality == 'usr':
    print_all_usernames(logs)
elif args.functionality == 'stats':
    if args.stat == 'rand':
        print_random_logs(logs, args.n)
    elif args.stat == 'all':
        print_conn_time_stats(logs)
    elif args.stat == 'usr':
        print_conn_time_stats_for_users(logs)
    elif args.stat == 'max':
        print_max_min_ip(logs)
