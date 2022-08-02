import base64
from stix_shifter_utils.stix_transmission.utils.RestApiClient import RestApiClient


class APIClient:

    PING_ENDPOINT = 'help/clientquery'
    QUERY_ENDPOINT = 'clientquery'
    RESULT_ENDPOINT = 'clientqueryresults/'
    SYNC_QUERY_ENDPOINT = 'query'

    def __init__(self, connection, configuration):
        self.endpoint_start = 'api/'
        auth = configuration.get('auth')
        self.headers = {}
        self.headers['Authorization'] = b"Basic " + base64.b64encode(
                (auth['username'] + ':' + auth['password']).encode('ascii'))
        self.connection = connection
        self.configuration = configuration
        self.timeout = connection['options'].get('timeout')

    def ping_box(self):
        endpoint = self.endpoint_start + self.PING_ENDPOINT
        return self.get_api_client().call_api(endpoint, 'GET', timeout=self.timeout)

    def create_search(self, query_expression):
        headers = {'Content-type': 'application/xml'}
        endpoint = self.endpoint_start + self.QUERY_ENDPOINT
        data = query_expression
        data = data.encode('utf-8')
        return self.get_api_client().call_api(endpoint, 'POST', headers, data=data, timeout=self.timeout)

    def get_search_results(self, search_id, offset, length):
        headers = {'Accept': 'application/json'}
        endpoint = self.endpoint_start + self.RESULT_ENDPOINT + search_id
        params = {'output': 'json', 'stats': '1', 'start': offset, 'count': length}
        return self.get_api_client().call_api(endpoint, 'GET', headers, urldata=params, timeout=self.timeout)

    def get_sync_query_results(self, relevance):
        headers = {}
        endpoint = self.endpoint_start + self.SYNC_QUERY_ENDPOINT
        params = {'relevance': relevance}
        return self.get_api_client().call_api(endpoint, 'GET', headers, urldata=params, timeout=self.timeout)

    def get_api_client(self):
        return RestApiClient(
            self.connection.get('host'),
            self.connection.get('port'),
            self.headers,
            cert_verify=self.connection.get('selfSignedCert', True),
            sni=self.connection.get('sni', None),
        )
