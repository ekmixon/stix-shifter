from stix_shifter_utils.stix_transmission.utils.RestApiClient import RestApiClient


class APIClient:
    """API Client to handle all calls."""
    
    def __init__(self, connection, configuration):
        """Initialization.
        :param connection: dict, connection dict
        :param configuration: dict,config dict"""

        headers = {}
        url_modifier_function = None
        default_api_version = 'v1.0'
        auth = configuration.get('auth')
        self.endpoint = '{api_version}/security/alerts'.format(api_version=default_api_version)
        self.host = connection.get('host')
        self.timeout = connection['options'].get('timeout')

        if auth and 'access_token' in auth:
            headers['Authorization'] = "Bearer " + auth['access_token']

        self.client = RestApiClient(connection.get('host'),
                                    connection.get('port', None),
                                    headers,
                                    url_modifier_function=url_modifier_function,
                                    cert_verify=connection.get('selfSignedCert', True),
                                    sni=connection.get('sni', None)
                                    )

    def ping_box(self):
        """Ping the endpoint."""
        params = {'$top': 1}
        return self.client.call_api(self.endpoint, 'GET', urldata=params, timeout=self.timeout)

    def run_search(self, query_expression, length):
        """get the response from azure_sentinel endpoints
        :param query_expression: str, search_id
        :param length: int,length value
        :return: response, json object"""
        headers = {'Accept': 'application/json'}
        params = {'$filter': query_expression, '$top': length}
        return self.client.call_api(self.endpoint, 'GET', headers, urldata=params, timeout=self.timeout)

    def next_page_run_search(self, next_page_url):
        """get the response from azure_sentinel endpoints
        :param next_page_url: str, search_id
        :return: response, json object"""
        headers = {'Accept': 'application/json'}
        url = next_page_url.split('?', maxsplit=1)[1]
        endpoint = f'{self.endpoint}?{url}'
        return self.client.call_api(endpoint, 'GET', headers, timeout=self.timeout)
