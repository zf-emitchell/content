from CommonServerPython import *

# IMPORTS #
import json
import requests
import urllib3
from typing import Dict, List

# Disable insecure warnings
urllib3.disable_warnings()

# CONSTANTS #
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
MAX_FETCH_SIZE = 20


# HELPER FUNCTIONS #
def create_incident_from_detection(detection: dict):
    """
    converts a detection object to an Incident object
    """
    labels = []
    for key, value in detection.items():
        labels.append({'type': key, 'value': json.dumps(value)})

        return {
            "name": f'{detection.get("id")} {detection.get("type_vname")}',
            "labels": labels,
            "rawJSON": json.dumps(detection)
        }


class Client:
    def __init__(self, vectra_url: str, api_token: str, verify: bool, proxies: dict, fetch_size: int):
        """
        :param vectra_url: IP or hostname of Vectra brain (ex https://www.example.com) - required
        :param api_token: API token for authentication when using API v2*
        :param verify: Boolean, controls whether we verify the server's TLS certificate
        :param proxies: Dictionary mapping protocol to the URL of the proxy.
        :param fetch_size: Max number of incidents to fetch in each cycle
        """
        self.fetch_size = fetch_size
        self.headers = {'Authorization': f'Token {api_token}'}
        self.base_url = vectra_url + '/api/v2.1/'
        self.verify = verify
        self.proxies = proxies

    def http_request(self, method='GET', url_suffix='', params=None, data=None) -> Dict:
        """
        Generic HTTP request to Vectra API.

        :param method: Request's method e.g., 'GET', 'POST', 'PATCH'
        :param url_suffix: The URL's suffix, usually indicates the API command
        :param params: Command parameters
        :param data: Other data to send the request with
        :return: .json() of the response if exists
        """
        full_url = self.base_url + url_suffix

        res = requests.request(
            method=method,
            url=full_url,
            headers=self.headers,
            params=params,
            data=data,
            verify=self.verify,
            proxies=self.proxies,
        )

        if not res.ok:
            raise ValueError(f'Error in API call to Vectra [{res.status_code:d}]. Reason: {res.text}')

        try:
            return res.json()

        except Exception:
            raise ValueError(f"Failed to parse http response to JSON format. Original response body: \n{res.text}")

    def fetch_incidents(self, last_run: Dict, t_score_gte: int, c_score_gte: int):
        """
        Fetches Detections from Vectra into Demisto Incidents

        :param last_run: Integration's last run
        """
        # Get the last id, if exists
        min_id = int(last_run.get('id')) if last_run and 'id' in last_run else 1

        # Fetch Detections
        params = {
            'min_id': min_id,
            'page_size': self.fetch_size,
            'page': 1,
            'ordering': 'last_timestamp',
            't_score_gte': t_score_gte,
            'c_score_gte': c_score_gte
        }
        raw_response = self.http_request(params=params, url_suffix='detections')

        # Detections -> Incidents, if exists
        incidents = []
        if 'results' in raw_response:
            count = raw_response.get('count')
            res = raw_response.get('results')  # type: ignore
            detections: List[Dict] = [res] if count == 1 else sorted(res, key=lambda h: h.get('id'))  # type: ignore

            try:
                for detection in detections:
                    incidents.append(create_incident_from_detection(detection))
                    min_id = max(min_id, int(detection.get('id', 0)))  # update last fetched id

                if incidents:
                    last_run = {'id': min_id + 1 if min_id > 0 else 1}

            except ValueError:
                raise

        return last_run, incidents


def get_detections_command(client: Client, **kwargs):
    """
    Detection objects contain all the information related to security events detected on the network.

    :QUERY PARAMETERS:
    :keyword fields: Filters objects listed
    :keyword page: Page number. Possible values are a positive integer or last
    :keyword page_size: Possible values are a positive integer or all
    :keyword ordering: Orders records by last timestamp, threat score and certainty score. Default is ascending order.
     Scores can sorted in descending order by prepending the query with “minus” symbol
    :keyword min_id: >= the id provided
    :keyword max_id: <= the id provided
    :keyword state: Filter by state: active, inactive, ignored, ignored for all
    :keyword type_vname: Filter by the detection type (verbose name)
    :keyword category: Filter by the detection category
    :keyword src_ip: Filter by source (ip address)
    :keyword t_score: Filter by threat score
    :keyword t_score_gte: Filter by threat score >= the score provided
    :keyword c_score: Filter by certainty score
    :keyword c_score_gte: Filter by certainty score >= the score provided
    :keyword last_timestamp: Filter by last timestamp
    :keyword host_id: Filter by id of the host object a detection is attributed to
    :keyword tags: Filter by a tag or a comma-separated list of tags
    :keyword destination: Filter by destination in the detection detail set
    :keyword proto: Filter by the protocol in the detection detail set
    :keyword dst_port: Filter by the destination port in the detection detail set
    :keyword inbound_ip: Filter by the inbound_ip in the relayed comm set
    :keyword inbound_proto: Filter by the inbound_proto in the relayed comm set
    :keyword inbound_port: Filter by the inbound_port in the relayed comm set
    :keyword inbound_dns: Filter by the inbound_dns in the relayed comm set
    :keyword outbound_ip: Filter by the outbound_ip in the relayed comm set
    :keyword outbound_proto: Filter by the outbound_proto in the relayed comm set
    :keyword outbound_port: Filter by the outbound_port in the relayed comm set
    :keyword outbound_dns: Filter by the outbound_dns in the relayed_comm_set
    :keyword dns_ip: Filter by the dns_ip in the dns_set
    :keyword dns_request: Filter by the dns_request in the dns_set
    :keyword resp_code: Filter by the resp_code in the dns_set
    :keyword resp: Filter by the resp in the dns_set
    """
    raw_response = client.http_request(params=kwargs, url_suffix='detections')
    count = raw_response.get('count')
    res = raw_response.get('results')  # type: ignore
    detections: List[Dict] = [res] if count == 1 else sorted(res, key=lambda h: h.get('id'))  # type: ignore

    headers = ['id', 'category', 'src_ip', 'threat', 'certainty', 'state', 'first_timestamp', 'tags',
               'targets_key_asset', 'type_vname']
    readable_output = tableToMarkdown(name='Detection table', t=detections, headers=headers)

    if 'detection_id' in kwargs:
        if 'summary' in detections[0]:
            summary = detections[0].get('summary')
            if summary:
                readable_output += '\n' + tableToMarkdown(name='Summary', t=summary[0], headers=summary[0].keys())

        if 'relayed_comm_set' in detections[0]:
            relayed_comm_set: List = detections[0].get('relayed_comm_set')  # type: ignore
            if not isinstance(relayed_comm_set, list):
                relayed_comm_set = [relayed_comm_set]
                if len(relayed_comm_set) > 0 and relayed_comm_set[0]:
                    wanted_keys = relayed_comm_set[0].keys().remove('url')
                    readable_output += '\n' + tableToMarkdown(name='Relayed Comm Set', t=relayed_comm_set[0],
                                                              headers=wanted_keys)

    context = []
    for detection in detections:
        context.append(createContext(
            {
                'DetectionId': detection.get('id'),
                'TypeVName': detection.get('type_vname'),
                'Category': detection.get('category'),
                'SrcIP': detection.get('src_ip'),
                'State': detection.get('state'),
                'Threat_Score': detection.get('threat'),
                'Certainty_Score': detection.get('certainty'),
                'TargetsKeyAsset': detection.get('targets_key_asset'),
                'FirstTimestamp': detection.get('first_timestamp'),
                'LastTimestamp': detection.get('last_timestamp'),
                'Tags': detection.get('tags'),
                'HostID': detection.get('host', '').split('/')[-1] if 'host' in detection else None
            }, removeNull=True)
        )
    outputs = {'Vectra.Detections(val.DetectionId==obj.DetectionId)': context}

    return readable_output, outputs, raw_response


# def update_detections_command(client: Client, id_list, **kwargs):
#     """
#     Detection objects contain all the information related to security events detected on the network.
#
#     :param id_list: list of Detection ID's to edit
#
#     :EDITABLE FIELDS:
#     :keyword detection: The name of the threat detected.
#     :keyword detection_type: The type of the threat detected.
#     :keyword category: The category of the vname attack detected
#     :keyword detection_category: The category type of the vname attack detected
#     :keyword src_ip: The source IP address of the host attributed to the security event.
#     :keyword state: The state of the detection.
#     :keyword t_score: The threat score attributed to the detection.
#     :keyword threat: The threat score attributed to the detection.
#     :keyword c_score: The certainty score attributed to the detection.
#     :keyword certainty: The certainty score attributed to the detection.
#     :keyword description: description of the event.
#     :keyword summary: The summary information for the detection
#     :keyword grouped_details: The detection details for the detection
#     :keyword tags: User defined tags added to the detection
#     :keyword note: User defined note for this detection.
#     """
#     kwargs['detectionIdList'] = argToList(id_list)
#     mock = {"detectionIdList": [30], 'mark_as_fixed': str(False)}
#     _ = client.http_request(method='PATCH', params=kwargs, url_suffix='detections', data=json.dumps(mock))
#     readable_output, outputs, raw_response = get_detections_command(client)
#
#     return readable_output, outputs, raw_response


def get_hosts_command(client: Client, **kwargs):
    """
    Host information includes data that correlates the host data to detected security events.

    :QUERY PARAMETERS:
    :keyword host_id:  Filter by host ID
    :keyword fields:  Filters objects listed
    :keyword page:  Page number. Possible values are a positive integer or last
    :keyword page_size:  Page size. Possible values are a positive integer or all
    :keyword ordering:  Orders records by last timestamp, threat score and certainty score.
        The default out sorts threat and certainty score in ascending order. Scores
        can sorted in descending order by prepending the query with “minus” symbol
    :keyword name: Filter by name
    :keyword state: Filter by state: active, inactive, suspended, ignored, ignored4all
    :keyword last_source: Filter by last_source (ip address)
    :keyword t_score: Filter by threat score
    :keyword t_score_gte: Filter by threat score >= the score provided
    :keyword c_score: Filter by certainty score
    :keyword c_score_gte: Filter by certainty score >= the score provided
    :keyword last_detection_timestamp: Filter by last_detection_timestamp
    :keyword tags: comma-separated list of tags, e.g., tags=baz | tags=foo,bar"
    :keyword key_assest: Filter by key asset: True, False
    :keyword mac_address: Filter by mac address
    """
    raw_response = client.http_request(params=kwargs, url_suffix='hosts')
    count = raw_response.get('count')
    res: List[Dict] = raw_response.get('results')  # type: ignore
    hosts: List[Dict] = [res] if count == 1 else sorted(res, key=lambda h: h.get('id'))  # type: ignore

    for host in hosts:
        if 'detection_set' in host:
            host['detection_ids'] = [host.split('/')[-1] for host in host.get('detection_set')]  # type: ignore

    headers = ['id', 'name', 'state', 'threat', 'certainty', 'last_source', 'url', 'assigned_to', 'owner_name',
               'first_timestamp', 'tags', 'note']
    readable_output = tableToMarkdown(name='Hosts table', t=hosts, headers=headers)

    context = []
    for host in hosts:
        context.append(
            {  # todo: go over with arseny
                'ID': host.get('id'),
                'Hostname': host.get('name'),
                'LastDetection': host.get('last_detection_timestamp'),
                'DetectionID': host.get('detection_ids'),
                'Threat_Score': host.get('threat'),
                'Certainty_Score': host.get('certainty'),
                'KeyAsset': host.get('key_asset'),
                'TargetsKeyAsset': host.get('targets_key_asset'),
                'State': host.get('state'),
                'IP': host.get('last_source')
            }
        )

    outputs = {'Vectra.Hosts(val.ID==obj.ID)': context}

    return readable_output, outputs, raw_response


def get_users_command(client: Client, **kwargs):
    """
    User information includes all data corresponding to user accounts

    :QUERY PARAMETERS:
    :keyword username: Filter by username
    :keyword role: Filter by role
    :keyword account_type: Filter by account type
    :keyword authentication_profile: Filter by authentication profile
    :keyword last_login_gte: Filters for User’s that have logged in since the given timestamp
    """
    raw_response = client.http_request(params=kwargs, url_suffix='users')
    count = raw_response.get('count')
    res: List[Dict] = raw_response.get('results')  # type: ignore
    users: List[Dict] = [res] if count == 1 else sorted(res, key=lambda h: h.get('id'))  # type: ignore

    headers = ['id', 'last_login', 'username', 'email', 'account_type', 'authentication_profile', 'role']
    readable_output = tableToMarkdown(name='Users table', t=users, headers=headers)

    context = []
    for user in users:
        context.append(
            {
                'ID': user.get('id'),
                'UserName': user.get('username'),
                'LastLogin': user.get('last_login'),
                'Email': user.get('email'),
                'AccountType': user.get('account_type'),
                'AuthenticationProfile': user.get('authentication_profile'),
                'Role': user.get('role'),
            }
        )
    outputs = {'Vectra.Users(val.ID==obj.ID)': context}

    return readable_output, outputs, raw_response


def search_command(client: Client, search_type: str, **kwargs):
    """
    The search API endpoint allows users to perform advanced search against hosts and detections

    :param client: Vectra Client

    :QUERY PARAMETERS:
    :param search_type: hosts or detections
    :keyword query_string: Query that needs to be performed
    :keyword page_size: Number of results returned per page. the default page_size is 50, max 5000
    """
    raw_response = client.http_request(params=kwargs, url_suffix=f'search/{search_type}')
    count = raw_response.get('count')
    results: List[Dict] = raw_response.get('results')  # type: ignore
    results: List[Dict] = [results] if count == 1 else sorted(results, key=lambda h: h.get('id'))  # type: ignore

    headers = ['id', 'threat', 'certainty', 'state', 'first_timestamp']

    readable_output = tableToMarkdown(name='Search results table', t=results, headers=headers)

    context = []
    for res in results:
        context.append(createContext(
            {
                'ID': res.get('id'),
                'Hostname': res.get('name'),
                'LastDetection': res.get('last_detection_timestamp'),
                'DetectionID': res.get('detection_ids'),
                'Threat_Score': res.get('threat'),
                'Certainty_Score': res.get('certainty'),
                'KeyAsset': res.get('key_asset'),
                'IP': res.get('last_source'),
                'DetectionId': res.get('id'),
                'TypeVName': res.get('type_vname'),
                'Category': res.get('category'),
                'SrcIP': res.get('src_ip'),
                'State': res.get('state'),
                'TargetsKeyAsset': res.get('targets_key_asset'),
                'FirstTimestamp': res.get('first_timestamp'),
                'LastTimestamp': res.get('last_timestamp'),
                'Tags': res.get('tags'),
                'HostID': res.get('host', '').split('/')[-1] if 'host' in res else None
            }, removeNull=True)
        )
    path = 'Hosts' if search_type == 'hosts' else 'Detections'
    outputs = {f'Vectra.{path}(val.ID==obj.ID)': context}

    return readable_output, outputs, raw_response


def get_triage_command(client: Client, **kwargs):
    """
    The rules branch can be used to retrieve a listing of configured Triage rules
    """
    raw_response = client.http_request(params=kwargs, url_suffix='rules')
    count = raw_response.get('count')
    res: List[Dict] = raw_response.get('results')  # type: ignore
    rules: List[Dict] = [res] if count == 1 else sorted(res, key=lambda h: h.get('name'))  # type: ignore

    headers = ['id', 'enabled', 'created_timestamp', 'is_whitelist', 'priority', 'active_detections',
               'total_detections', 'template', 'detection_category', 'triage_category', 'detection']
    readable_output = tableToMarkdown(name='Rules table', t=rules, headers=headers)

    context = []
    for rule in rules:
        temp = {
            'ID': rule.get('name'),
            'SmartCategory': rule.get('smart_category'),
            'Description': rule.get('description'),
            'Type': rule.get('type_vname'),
            'Category': rule.get('category'),
            'Created': rule.get('created_timestamp'),
            'LastUpdate': rule.get('last_timestamp'),
            'Host': rule.get('host'),
            'IP': rule.get('ip'),
            'Priority': rule.get('priority'),
            'Remote': [
                {
                    'IP': rule.get('remote1_ip'),
                    'Protocol': rule.get('remote1_proto'),
                    'Port': rule.get('remote1_port'),
                    'DNS': rule.get('remote1_dns')
                },
                {
                    'IP': rule.get('remote2_ip'),
                    'Protocol': rule.get('remote2_proto'),
                    'Port': rule.get('remote2_port'),
                    'DNS': rule.get('remote2_dns')
                }
            ]
        }  # type: ignore
        kerberos = {
            'Account': rule.get('remote1_kerb_account'),
            'Service': rule.get('remote1_kerb_service')
        }
        if kerberos['Account'] or kerberos['Service']:
            temp['Remote'] = {'Kerberos': kerberos}  # type: ignore

        remove_nulls_from_dictionary(temp)
        context.append(temp)

    outputs = {'Vectra.Rules(val.ID==obj.ID)': context}

    return readable_output, outputs, raw_response


def get_proxies_command(client: Client, **kwargs):
    """
    The proxies API can be used to manage proxy IP addresses (internal or external) in Cognito. The API can
    be used to retrieve the current list of proxy IP addresses or to create new proxy objects in Cognito.

    :param client: Vectra Client
    """
    raw_response = client.http_request(params=kwargs, url_suffix='settings/proxy')
    res, count = raw_response.get('results'), raw_response.get('count')  # type: ignore
    proxies: List[Dict] = [res] if count == 1 else sorted(res, key=lambda h: h.get('id'))  # type: ignore

    headers = ['id', 'source', 'considersProxy', 'address']
    readable_output = tableToMarkdown(name='Rules table', t=proxies, headers=headers)

    context = []
    for proxy in proxies:
        context.append(createContext(
            {
                'ID': proxy.get('id'),
                'Source': proxy.get('source'),
                'ConsidersProxy': proxy.get('considersProxy'),
                'Address': proxy.get('address'),
            }, removeNull=True)
        )
    outputs = {'Vectra.Proxy(val.ID==obj.ID)': context}

    return readable_output, outputs, raw_response


def test_module(client: Client, last_run: dict):
    """
    Performs basic tests to insure API connection, and to test integration's parameters
    """
    client.fetch_incidents(last_run=last_run)  # will handle any bad request/bad api token
    return 'ok'


# COMMANDS MANAGER / SWITCH PANEL #
def main():
    api_token = demisto.getParam('token')
    dict().values()

    # Remove trailing slash to prevent wrong URL path to service
    server_url = demisto.getParam('server').rstrip('/')

    # Fetch only detections that have greater or equal Certainty and Threat scores
    c_score_gte, t_score_gte = demisto.params().get('c_score_gte', 0), demisto.params().get('t_score_gte', 0)

    # Remove proxy if not set to true in params
    proxies = handle_proxy()

    fetch_size = demisto.params().get('fetch_size', 20)
    verify_certificate = not demisto.params().get('insecure', False)

    LOG(f'Command being called is {demisto.command()}')
    try:
        # create a new Client instance
        client = Client(
            vectra_url=server_url,
            verify=verify_certificate,
            api_token=api_token,
            proxies=proxies,
            fetch_size=min(fetch_size, MAX_FETCH_SIZE)
        )

        # execute the current command
        if demisto.command() == 'test-module':
            results = test_module(client, last_run=demisto.getLastRun())
            demisto.results(results)

        elif demisto.command() == 'fetch-incidents':
            next_run, incidents = client.fetch_incidents(
                last_run=demisto.getLastRun(),
                c_score_gte=int(c_score_gte),
                t_score_gte=int(t_score_gte)
            )
            demisto.setLastRun(next_run)
            demisto.incidents(incidents)

        elif demisto.command() == 'vectra-get-detections':
            return_outputs(*get_detections_command(client, **demisto.args()))

        # elif demisto.command() == 'vectra-update-detections':
        #     return_outputs(*update_detections_command(client, **demisto.args()))

        elif demisto.command() == 'vectra-get-users':
            return_outputs(*get_users_command(client, **demisto.args()))

        # elif demisto.command() == 'vectra-update-users':
        # return_outputs(*update_users_command(client, **demisto.args()))

        elif demisto.command() == 'vectra-get-hosts':
            return_outputs(*get_hosts_command(client, **demisto.args()))

        # elif demisto.command() == 'vectra-update-hosts':
        #     return_outputs(*update_hosts_command(client, **demisto.args()))

        elif demisto.command() == 'vectra-search':
            return_outputs(*search_command(client, **demisto.args()))

        elif demisto.command() == 'vectra-triage':
            return_outputs(*get_triage_command(client, **demisto.args()))

        elif demisto.command() == 'vectra-proxies':
            return_outputs(*get_proxies_command(client, **demisto.args()))  # todo: Page Not Found

    # Log exceptions
    except Exception as ex:
        if demisto.command() == 'fetch-incidents':
            LOG(str(ex))
            raise
        else:
            return_error(str(ex))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()

# todo: add detection for an account/host (new param)
# todo: add max fetch to yml (20)
# todo: add threshold
# todo: go over each command params and make sure it's in the keywords
# todo: add c_score and t_score to docs
