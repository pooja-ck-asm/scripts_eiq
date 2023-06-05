#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Script for scaning the vulnerabilities from installed applications .
:copyright: (c) 2023 by EclecticIQ.
:license: MIT, see LICENSE for more details.

To run it:
1. Install python and python required modules mentioned in requirements.txt
2. Install go lang, install https://github.com/facebookincubator/nvdtools and make sure they are available
3. Download the NVD feed with .json.gz format
4. Run the script using the required command line arguments using installed python version

"""

import argparse
import os
import sys
import datetime
import inspect
import subprocess

main_dir = os.path.dirname(os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe()))))
sys.path.append(main_dir)

from api import api


class ScanCVE:
    splitter = ','

    def __init__(self, domain=None, username=None, password=None, host_identifier=None, nvd_feed=None, platform=None):
        self.host_identifier = host_identifier
        self.er_api = api.ErAPI(username=username, password=password, domain=domain)
        self.nvd_feed = nvd_feed
        self.platform = platform
        self.sql_windows = """SELECT 'a' AS part, publisher AS vendor, name AS product, version \
        AS version FROM programs WHERE name IS NOT NULL AND name <> '';"""
        self.sql_darwin = """SELECT 'a' AS part, '' AS vendor, bundle_name AS product, bundle_version AS version FROM apps WHERE bundle_name IS NOT NULL AND bundle_name <> '';"""
        self.sql_ubuntu = """SELECT 'a' AS part, '' AS vendor, name AS product, version AS version FROM deb_packages WHERE name IS NOT NULL AND name <> '';"""
        self.sql_rhel = """SELECT 'a' AS part, '' AS vendor, name AS product, version AS version FROM rpm_packages WHERE name IS NOT NULL AND name <> '';"""
        self.command = """echo '{0}' | csv2cpe -x -lower -cpe_part=1 -cpe_vendor=2 -cpe_product=3 \
        -cpe_version=4 | cpe2cve -cpe 1 -e 1 -cve 1 {1}"""

    def run(self):
        if self.host_identifier:
            hosts_platform_dict = {self.platform: [self.host_identifier]}
        else:
            all_hosts = self.er_api.get_nodes_with_action_online()
            hosts_platform_dict = self.get_platform_hosts_dict(all_hosts)
        for platform, hosts_array in hosts_platform_dict.items():
            if platform == 'windows':
                sql = self.sql_windows
            elif platform == 'darwin':
                sql = self.sql_darwin
            elif platform == 'ubuntu':
                sql = self.sql_ubuntu
            elif platform == 'rhel':
                sql = self.sql_rhel

            results = self.er_api.query_live(sql=sql, host_identifiers=hosts_array)
            csv_array_dict = {}
            for host_identifier, data_node_dict in results.items():
                csv_array_dict[host_identifier] = self.get_installed_programs_csv(data_node_dict['data'])

            for host, csv_array in csv_array_dict.items():
                vulnerable_found = False
                for csv in csv_array:
                    command = self.command.format(csv, self.nvd_feed)
                    output = subprocess.getoutput(command)
                    if output:
                        vulnerable_found = True
                        part, vendor, product, version = csv.split(self.splitter)
                        print(
                            "Vulnerable found for the application '{0}' with version '{1}' in the host '{2}' with the CVE: {3}".format(product, version, host, output))
                if not vulnerable_found:
                    print("No vulnerable found in the host: {}".format(host))

    @staticmethod
    def get_platform_hosts_dict(all_hosts):
        hosts_platform_dict = {}
        for host in all_hosts:
            if 'os_info' in host and 'platform' in host['os_info']:
                platform = host['os_info']['platform']
            elif 'host_details' in host and 'osquery_info' in host['host_details'] and 'build_platform' in host['host_details']['osquery_info']:
                if host['host_details']['osquery_info']['build_platform'] == 'windows' or host['host_details']['osquery_info']['build_platform'] == 'darwin':
                    platform = host['host_details']['osquery_info']['build_platform']
                else:
                    if 'os_info' in host and 'name' in host['os_info'] and host['os_info']['name']:
                        if host['os_info']['name'].startswith('Ubuntu'):
                            platform = "ubuntu"
                        elif host['os_info']['name'].startswith('Red Hat Enterprise'):
                            platform = "rhel"
            if platform in hosts_platform_dict:
                hosts_platform_dict[platform].append(host['host_identifier'])
            else:
                hosts_platform_dict[platform] = [host['host_identifier']]
        return hosts_platform_dict

    def get_installed_programs_csv(self, data):
        filtered_list = []
        for result in data:
            vendor_word_list = result['vendor'].split(" ")
            product = result['product']
            vendor = result['vendor']
            for item in vendor_word_list:
                if item == "The":
                    continue
                else:
                    vendor = item.lower()
                    break
            product_word_list = result['product'].split(" ")
            for item in product_word_list:
                if item == "The":
                    continue
                else:
                    product = item.lower()
                    break
            filtered_list.append(
                self.splitter.join([result['part'], vendor.replace(',', ''), product.replace(',', ''), result['version']]))
        return filtered_list


def main(domain=None, username=None, password=None, host_identifier=None, nvd_feed=None, platform=None):
    scve = ScanCVE(domain=domain, username=username, password=password, host_identifier=host_identifier, nvd_feed=nvd_feed, platform=platform)
    return scve.run()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='User credentials.')
    parser.add_argument('--username', help='Admin username', required=True)
    parser.add_argument('--domain', help='Domain/Ip of the server', required=True)
    parser.add_argument('--password', help='Admin password', required=True)
    parser.add_argument('--host_identifier', help='Host Identifier of the Host', required=False)
    parser.add_argument('--platform', help='Platform of the Host(windows/ubuntu/rhel/darwin)', required=False)
    parser.add_argument('--nvd_feed', help='Path of the json.gz formatted nvd feed file', required=True)
    args = parser.parse_args()

    main(args.domain, args.username, args.password, args.host_identifier, args.nvd_feed, args.platform)