#!/usr/bin/env python
# -*- coding: iso-8859-1 -*-
# -*- coding: utf-8 -*-
#
# LittleSnitch Log Statistics Exporter
# Exports statistics of internal LittleSnitch log data
#
# Florian Roth

__version__ = "0.1.0"

import sys
import re
import argparse
import datetime
import subprocess
import logging
import csv
import platform
import ipaddress


def collect_logs(min):
    """
    Collect all logs of the last x minutes
    """
    date_start = datetime.datetime.now() - datetime.timedelta(minutes=min)
    start_string = date_start.strftime('%Y-%m-%d %H:%M:%S')

    # Call LittleSnitch Command Line Utility
    log_output = subprocess.Popen(
        "littlesnitch log-traffic -b '%s'" % start_string,
        shell=True, stdout=subprocess.PIPE).stdout.read()

    # Errors 
    if b'run as root' in log_output:
        Log.error("The script has to be run as root")
        sys.exit(1)
    elif b'Please enable access' in log_output:
        Log.error("Access to log data is denied.")
        print("Original message: %s" % log_output.decode('utf-8'))
        sys.exit(1)
    else:
        # Debug
        if args.debug:
            print(log_output.decode('utf-8')[:128])

    # Split the lines
    log_lines = []
    reader = csv.DictReader(log_output.decode('utf-8').split("\n"), delimiter=",", quotechar='"')
    for line in reader:
        log_lines.append(line)

    return log_lines


def generate_statistics(log_lines, sort_key):
    """
    Generate statistics from log lines
    """
    stats = {}
    for line in log_lines:
        # Allowed ot denied
        action = "allowed"
        if int(line['denyCount']) > 0:
            action = "denied"
        # Key is a combination of direction-connectionExecutable-ipAddress-remoteHostname-port
        # Lines are dicts:
        # {'date': '2021-01-02T09:42:56Z', 'direction': 'out', 'uid': '501', 'ipAddress': '140.82.112.25',
        # 'remoteHostname': 'alive.github.com', 'protocol': '6', 'port': '443', 'connectCount': '0', 'denyCount': '0',
        # 'byteCountIn': '25', 'byteCountOut': '29', 'connectingExecutable':
        # '/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/87.0.4280.88/
        # Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper',
        # 'parentAppExecutable': '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'}
        combo_string = "%s;%s;%s;%s;%s;%s" % (line['direction'], line['connectingExecutable'], line['ipAddress'],
                                              line['remoteHostname'], line['port'], action)
        try:
            stats[combo_string] += 1
        except KeyError:
            stats[combo_string] = 1
            pass

    combo_list = []
    for combo, count in stats.items():
        if args.debug:
            print("COUNT: %d COMBO: %s" % (count, combo))
        combo_split = combo.split(";")
        combo_dict = {
            'direction': combo_split[0],
            'connectingExecutable': combo_split[1],
            'ipAddress': combo_split[2],
            'remoteHostname': combo_split[3],
            'port': int(combo_split[4]),
            'action': combo_split[5],
            'count': count,
        }
        combo_list.append(combo_dict)

    # Sort the dictionary
    combo_list_sorted = sorted(combo_list, key=lambda k: k[sort_key])

    return combo_list_sorted


def filter_stats(combo_list_sorted):
    """
    Filter the statistics and show only highlights
    """
    allowed_hosts = ['icloud.com', 'icloud-content.com', 'apple.com', 'cdn-apple.com', 'mzstatic.com',
                     'googleapis.com', 'google.com', 'amazonaws.com', '104.125.71.134', 'local', '239.255.255.250',
                     'live.com', 'digicert.com', 'amazontrust.com', 'apple-cloudkit.com', 'letsencrypt.org',
                     'lencr.org', 'verisign.com', 'sectigo.com', 'appcenter.ms', 'python.org', 'pypi.org',
                     'sharepoint.com', 'office.com', 'cloudapp.net', 'office365.com', 'microsoft.com', 'sfx.ms',
                     'outlook.com', 'windows.net', 'azurewebsites.net', 'office.net', 'skype.com', 'msecnd.net',
                     'exp-tas.com', 'yahoo.com', 'networking.apple']
    browsers = ['Google Chrome.app', 'com.apple.WebKit.Networking', 'Firefox.app', 'Opera', 'Brave Browser.app']
    vpn_software = ['openvpn']
    dns = ['mDNSResponder']
    re_app_split = re.compile(r'[^\w]')

    # New list relevant connections
    new_combo_list = []
    for c in combo_list_sorted:
        skip = False
        # Incoming
        if c['direction'] == "in":
            continue
        # Private IP addresses
        if ipaddress.ip_address(c['ipAddress']).is_private:
            skip = True
        # Browser web access
        for b in browsers:
            if b in c['connectingExecutable'] and ( c['port'] == 443 or c['port'] == 80 or c['port'] == 5228):
                skip = True
        # DNS responder
        for d in dns:
            if d in c['connectingExecutable'] and (c['port'] == 53 or c['port'] == 5353):
                skip = True
            for ah in allowed_hosts:
                if d in c['connectingExecutable'] and ah in c['remoteHostname']:
                    skip = True
        # VPN
        for v in vpn_software:
            if v in c['connectingExecutable']:
                if c['port'] == 1194 or c['port'] == 443:
                    skip = True
        # Allowed hosts
        for ah in allowed_hosts:
            if c['remoteHostname'].endswith(".%s" % ah):
                skip = True
            if c['ipAddress'] == ah:
                skip = True
        # Keyword in AppName found in Remote Host
        for keyword in re_app_split.split(c['connectingExecutable'].lower()):
            if len(keyword) < 4:
                continue
            if keyword in c['remoteHostname']:
                skip = True
        if not skip:
            new_combo_list.append(c)

    return new_combo_list


def print_stats(combo_list_sorted):
    """
    Print statistics as log lines
    """

    # Print the sorted statistics
    for c in combo_list_sorted:
        Log.info("APP: '%s' DIRECTION: %s IP: %s HOST: '%s' PORT: %s ACTION: %s COUNT: %s" % (
             c['connectingExecutable'],
             c['direction'].upper(),
             c['ipAddress'],
             c['remoteHostname'],
             c['port'],
             c['action'].upper(),
             c['count']
        ))


if __name__ == '__main__':

    # Parse Arguments
    parser = argparse.ArgumentParser(description='LittleSnitch Log Statistics Exporter')
    parser.add_argument('-m', metavar='minutes', default='60', help='Process the logs of that X minutes (default=60)')
    parser.add_argument('-l', help='Log file (default: littlesnitch-log-export.log)', metavar='logfile', default=r'littlesnitch-log-export.log')
    parser.add_argument('-s', metavar='sort-key', default='connectingExecutable',
                        help='Key to sort the output statistics (available: direction, connectingExecutable, '
                             'ipAddress, remoteHostname, port, count) (default=connectingExecutable)')
    parser.add_argument('--debug', action='store_true', default=False, help='Debug output')
    parser.add_argument('--noteworthy', action='store_true', default=False, help='Show connections considered interesting (Florian\'s magic)')
    args = parser.parse_args()

    # Logging
    logFormatter = logging.Formatter("%(asctime)s {}: %(message)s".format(platform.node()))
    Log = logging.getLogger(__name__)
    Log.setLevel(logging.INFO)
    # File Handler
    fileHandler = logging.FileHandler(args.l)
    fileHandler.setFormatter(logFormatter)
    Log.addHandler(fileHandler)
    # Console Handler
    consoleHandler = logging.StreamHandler(sys.stdout)
    consoleHandler.setFormatter(logFormatter)
    Log.addHandler(consoleHandler)

    # Collect the logs
    log_lines = collect_logs(int(args.m))
    stats = generate_statistics(log_lines, args.s)
    if args.noteworthy:
        stats = filter_stats(stats)
    print_stats(stats)
