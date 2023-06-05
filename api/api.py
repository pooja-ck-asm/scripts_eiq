#!/usr/bin/env python
# -*- coding: utf-8 -*-
import json
import time

import requests
import websocket
from websocket import create_connection
import ssl
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

TIMEOUT_SECS = 30


class ErAPI:
    def __init__(self, domain=None, username=None, password=None):
        """
        This method allows you to create ER base API object along with a access token created.
        :return: None
        """
        self.username = username
        self.password = password
        self.version = 0
        self.max_retries = 5
        self.domain = domain
        self.base = f"https://{domain}/esp-ui/services/api/v1"
        self.AUTH_TOKEN = None
        self.max_tries = 1
        self.max_listen_for = 2*60  # 60 sec * 2 = 2 min

        if username is None or password is None:
            raise ApiError("You must supply username and password.")
        self.fetch_token()

    def fetch_token(self):
        """
        This method allows you to create an access token created.
        :return: None on success, error in case of any error
        """
        url = f"{self.base}/login"
        payload = {'username': self.username, 'password': self.password}
        try:
            response = _return_response_and_status_code(requests.post(
                url, json=payload, headers={},
                verify=False, timeout=TIMEOUT_SECS))
            if response['response_code'] == 200:
                if 'status' in response['results'] and response['results']['status'] == "failure":
                    raise ApiError("Invalid username and or password.")
                self.AUTH_TOKEN = response['results']['token']
        except requests.RequestException as e:
            return dict(error=str(e))

    def get_nodes(self):
        """
        This API allows you to get all the nodes registered.
        :return: JSON response that contains list of nodes.
        """
        url = f"{self.base}/hosts"
        headers = {'x-access-token': self.AUTH_TOKEN}
        try:
            response = requests.post(
                url, headers=headers,
                verify=False, timeout=TIMEOUT_SECS)
        except requests.RequestException as e:
            return dict(error=str(e))

        return _return_response_and_status_code(response)

    def get_action_status_of_all_hosts(self):
        """
        This API allows you to get response action status/degraded status of all nodes.
        :return: JSON response that contains list of nodes.
        """
        url = f"{self.base}/response/status/all"
        headers = {'x-access-token': self.AUTH_TOKEN}
        try:
            response = requests.get(
                url, headers=headers,
                verify=False, timeout=TIMEOUT_SECS)
        except requests.RequestException as e:
            return dict(error=str(e))
        results = _return_response_and_status_code(response)['results']['data']
        return results

    def get_nodes_with_action_online(self, platform=None):
        """
        This API allows you to get all the nodes registered.
        :return: JSON response that contains list of nodes.
        """
        active_hosts = []
        url = f"{self.base}/hosts"
        body = {}
        if platform:
            body['platform'] = platform
        headers = {'x-access-token': self.AUTH_TOKEN}
        try:
            response = requests.post(
                url, headers=headers, json=body,
                verify=False, timeout=TIMEOUT_SECS)
        except requests.RequestException as e:
            return dict(error=str(e))
        results = _return_response_and_status_code(response)
        hosts = results['results']['data']['results']  # Final hosts array

        # To fetch response action status of all hosts, Can be used to find degraded status
        response_status_array = self.get_action_status_of_all_hosts()  # Final array of hosts

        # To filter only hosts with response action online i.e. not degraded
        for host in hosts:
            for response_host in response_status_array:
                if host['host_identifier'] == response_host['hostIdentifier'] and \
                        response_host['endpointOnline'] is True and response_host['host_degraded'] is False:
                    active_hosts.append(host)
                    break
        return active_hosts

    def get_alerts(self, data):
        """
        This API allows you to get all the nodes registered.
        :param data: full payload to be passed to the alerts api
        :return: JSON response that contains list of nodes.
        """
        url = f"{self.base}/alerts"
        headers = {'x-access-token': self.AUTH_TOKEN}
        try:
            response = requests.post(
                url, headers=headers, json=data,
                verify=False, timeout=TIMEOUT_SECS)
        except requests.RequestException as e:
            return dict(error=str(e))

        return _return_response_and_status_code(response)

    def send_distributed_query(self, sql=None, tags=None, host_identifiers=None, os=None):
        """
        Send a query to nodes.
        This API allows you to execute an on-demand query on the nodes.
        :param sql: The sql query to be executed
        :param tags: Specify the array of tags.
        :param host_identifiers: Specify the host_identifier array.
        :param os: Specify the os names array.
        :return: JSON response that contains query_id.
        """
        payload = {
            "query": sql
        }
        if host_identifiers:
            payload['nodes'] = ','.join(host_identifiers)
        if tags:
            payload['tags'] = ','.join(tags)
        if os:
            payload['os_name'] = os

        headers = {'x-access-token': self.AUTH_TOKEN, 'content-type': 'application/json'}
        url = f"{self.base}/distributed/add"
        # Adding live query through REST API
        try:
            response = requests.post(
                url, json=payload, headers=headers,
                verify=False, timeout=TIMEOUT_SECS)
        except requests.RequestException as e:
            return dict(error=str(e))
        response = _return_response_and_status_code(response)
        return response

    def query_live(self, sql=None, tags=None, host_identifiers=None, os=None):
        """
        Send a query to nodes.
        This API allows you to execute an on-demand query on the nodes.
        :param sql: The sql query to be executed
        :param tags: Specify the array of tags.
        :param host_identifiers: Specify the host_identifier array.
        :param os: Specify the os names array.
        :return: JSON response that contains query_id.
        """
        response = self.send_distributed_query(sql=sql, tags=tags, host_identifiers=host_identifiers, os=os)
        results = self.live_query_results(response['results']['data']['query_id'],
                                          response['results']['data']['onlineNodes'],
                                          response['results']['data']['online_nodes_details'])
        return results

    def live_query_results(self, query_id, online_nodes, online_nodes_dict):
        """
        Sends live query results by fetching them from web socket.
        This API allows you to execute an on-demand query on the nodes.
        :param query_id: Id of the distributed query triggered
        :param online_nodes: No.of nodes, To which query was sent.
        :param online_nodes_dict: Information of nodes, To which query was sent.
        :return: JSON response that results for the live query.
        """
        data = {}
        received_count = 0
        # Listening for results through web socket
        for i in range(self.max_tries):
            #  If any exception on ws connection, it tries for 5 times atmost then quits
            try:
                conn = create_connection(f"wss://{self.domain}/esp-ui/distributed/result",
                                         sslopt={"cert_reqs": ssl.CERT_NONE})
                conn.send(str(query_id))
                conn.recv()  # Ignoring as its informative string but not data
                start_time = time.time()
                while time.time() - start_time < self.max_listen_for and received_count < online_nodes:
                    result = conn.recv()
                    result = json.loads(result)
                    received_count += 1

                    for node in online_nodes_dict:
                        if result['node']['id'] == node['node_id']:
                            data[node['host_identifier']] = {'data': result['data'], 'node': node}
                            break
                conn.close()
            except websocket.WebSocketConnectionClosedException:
                # Should catch ConnectionClosed exception to try connecting again and tries for 5 times at most
                pass
            if received_count >= online_nodes:
                break
        return data

    def get_distributed_query_results(self, query_id):
        """
        Retrieve the query results based on the query_id query.
        This API uses websocket connection for getting data.
        :param query_id: Query id for which the results to be fetched
        :return: Stream data of a query executed on nodes.
        """
        conn = create_connection(f"wss://{self.domain}/esp-ui/distributed/result",
                                 sslopt={"cert_reqs": ssl.CERT_NONE})

        conn.send(str(query_id))
        conn.recv()
        return conn

    def get_query_data(self, query_name=None, host_identifier=None, start=1, limit=100):
        """
        Fetches results of a scheduled query
        :param query_name: query name of the results.
        :param host_identifier: host identifier to filter the results.
        :param start: offset for the results.
        :param limit: limit for the results.
        :return: JSON response that contains query results.
        """
        payload = {'host_identifier': host_identifier, 'query_name': query_name, 'start': start, 'limit': limit}
        headers = {'x-access-token': self.AUTH_TOKEN, 'content-type': 'application/json'}
        url = f"{self.base}/hosts/recent_activity"
        try:
            response = requests.post(
                url, json=payload, headers=headers,
                verify=False, timeout=TIMEOUT_SECS)
        except requests.RequestException as e:
            return dict(error=str(e))
        return _return_response_and_status_code(response)

    def search_query_data(self, search_conditions):
        """
        Searches for the results among all hosts
        :param search_conditions: json of conditions.
        :return: JSON response that contains query results.
        """
        payload = search_conditions
        headers = {'x-access-token': self.AUTH_TOKEN, 'content-type': 'application/json'}
        url = f"{self.base}/search"
        try:
            response = requests.post(
                url, json=payload, headers=headers,
                verify=False, timeout=TIMEOUT_SECS)
        except requests.RequestException as e:
            return dict(error=str(e))
        return _return_response_and_status_code(response)

    def get_carves(self, host_identifier=None):
        """
        Retrieve file carving  list.
        This API allows you to execute an on-demand query on the nodes.
        :param host_identifier: Node host_identifier for which the carves to fetched.
        :return: JSON response that contains list of file carving done.
        """
        payload = {'host_identifier': host_identifier}
        headers = {'x-access-token': self.AUTH_TOKEN, 'content-type': 'application/json'}
        url = f"{self.base}/carves"
        try:
            response = requests.post(
                url, json=payload, headers=headers,
                verify=False, timeout=TIMEOUT_SECS)
        except requests.RequestException as e:
            return dict(error=str(e))
        return _return_response_and_status_code(response)

    def get_carve_by_query_id(self, query_id=None, host_identifier=None):
        """
        Download the carved file using the sesion_id.
        This API allows you to execute an on-demand query on the nodes.
        :param session_id: session id of a carve to be downloaded.
        :return: File content.
        """
        headers = {'x-access-token': self.AUTH_TOKEN, 'content-type': 'application/json'}
        payload = {'host_identifier': host_identifier, 'query_id': query_id}
        try:
            response = requests.post(
                f"{self.base}/carves/query", headers=headers, json=payload, verify=False, timeout=TIMEOUT_SECS)

        except requests.RequestException as e:
            return dict(error=str(e))

        return _return_response_and_status_code(response)

    def download_carve(self, session_id=None):
        """
        Download the carved file using the sesion_id.
        This API allows you to execute an on-demand query on the nodes.
        :param session_id: session id of a carve to be downloaded.
        :return: File content.
        """
        headers = {'x-access-token': self.AUTH_TOKEN}
        try:
            response = requests.get(
                f"{self.base}/carves/download/" + session_id, headers=headers, verify=False)
            return response.content
        except requests.RequestException as e:
            return dict(error=str(e))

    def take_action(self, data):
        """
        This API allows you to get all the nodes registered.
        :return: JSON response that contains list of nodes.
        """
        url = f"{self.base}/response/add"
        headers = {'x-access-token': self.AUTH_TOKEN}
        try:
            response = requests.post(
                url, headers=headers, json=data,
                verify=False, timeout=TIMEOUT_SECS)
        except requests.RequestException as e:
            return dict(error=str(e))

        return _return_response_and_status_code(response)

    def get_action_status(self, command_id):
        """
        This API allows you to get all the nodes registered.
        :return: JSON response that contains list of nodes.
        """
        url = f"{self.base}/response/{command_id}"
        headers = {'x-access-token': self.AUTH_TOKEN}
        try:
            response = requests.get(
                url, headers=headers,
                verify=False, timeout=TIMEOUT_SECS)
        except requests.RequestException as e:
            return dict(error=str(e))

        return _return_response_and_status_code(response)


class ApiError(Exception):
    pass


def _return_response_and_status_code(response, json_results=True):
    """
    Output the requests response content or content as json and status code
    :rtype : dict
    :param response: requests response object
    :param json_results: Should return JSON or raw content
    :return: dict containing the response content and/or the status code with error string.
    """
    if response.status_code == requests.codes.ok:
        return dict(results=response.json() if json_results else response.content, response_code=response.status_code)
    elif response.status_code == 400:
        return dict(
            error='package sent is malformed.',
            response_code=response.status_code)
    elif response.status_code == 404:
        return dict(error='Requested URL not found.', response_code=response.status_code)
    else:
        return dict(response_code=response.status_code)