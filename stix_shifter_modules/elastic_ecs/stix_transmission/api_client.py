import base64
from stix_shifter_utils.stix_transmission.utils.RestApiClient import RestApiClient
from stix_shifter_utils.utils import logger
import json
import re

DEFAULT_LIMIT = 10000


class APIClient():
    PING_ENDPOINT = '_cluster/health?pretty'

    def __init__(self, connection, configuration):
        self.logger = logger.set_logger(__name__)
        headers = {}
        url_modifier_function = None
        auth = configuration.get('auth')
        self.indices = connection.get('indices', None)

        if self.indices and type(self.indices) == str:
            self.indices = self.indices.split(",")

        if isinstance(self.indices, list):  # Get list of all indices
            self.indices = [i.strip(' ') for i in self.indices]
            self.indices = ",".join(self.indices)

        self.endpoint = f'{self.indices}/_search' if self.indices else '_search'
        if auth:
            if 'username' in auth and 'password' in auth:
                headers['Authorization'] = b"Basic " + base64.b64encode(
                    (auth['username'] + ':' + auth['password']).encode('ascii'))
            elif 'api_key' in auth and 'id' in auth:
                headers['Authorization'] = b"ApiKey " + base64.b64encode(
                    (auth['id'] + ':' + auth['api_key']).encode('ascii'))
            elif 'access_token' in auth:
                headers['Authorization'] = "Bearer " + auth['access_token']

        self.client = RestApiClient(connection.get('host'),
                                    connection.get('port'),
                                    headers,
                                    url_modifier_function=url_modifier_function,
                                    cert_verify=connection.get('selfSignedCert', True),
                                    sni=connection.get('sni', None)
                                    )

        self.timeout = connection['options'].get('timeout')

    def ping_box(self):
        return self.client.call_api(self.PING_ENDPOINT, 'GET',timeout=self.timeout)

    def run_search(self, query_expression, offset=None, length=DEFAULT_LIMIT):
        headers = {'Content-Type': 'application/json'}
        endpoint = self.endpoint

        uri_search = False  # For testing and debugging two ways of _search API methods

        # URI Search
        if uri_search:
            if query_expression is not None:
                # update/add size value
                if length is not None:
                    if re.search(r"&size=\d+", query_expression):
                        query_expression = re.sub(r"(?<=&size=)\d+", str(length), query_expression)
                    else:
                        query_expression = f'{query_expression}&size={length}'

                # add offset to query expression
                if offset is not None:
                    query_expression = f'{query_expression}&from={offset}'

            # addition of QueryString to API END point
            endpoint = f'{endpoint}?q={query_expression}'

            return self.client.call_api(endpoint, 'GET', headers, timeout=self.timeout)
        else:
            # add size value
            if length is not None:
                endpoint = f"{endpoint}?size={length}"

            # add offset value
            if offset is not None:
                endpoint = f"{endpoint}&from={offset}"

            data = {
                "_source": {
                    "includes": ["@timestamp", "source.*", "destination.*", "event.*", "client.*", "server.*",
                                 "host.*","network.*", "process.*", "user.*", "file.*", "url.*", "registry.*", "dns.*"]
                },
                "query": {
                    "query_string": {
                      "query": query_expression
                    }
                }
            }

            self.logger.debug(f"URL endpoint: {endpoint}")
            self.logger.debug(f"URL data: {json.dumps(data)}")

            return self.client.call_api(endpoint, 'GET', headers, data=json.dumps(data), timeout=self.timeout)
