from stix_shifter_utils.modules.base.stix_transmission.base_sync_connector import BaseSyncConnector
from stix_shifter_utils.stix_transmission.utils.RestApiClient import RestApiClient
from stix2matcher.matcher import Pattern
from stix2matcher.matcher import MatchListener
from stix2validator import validate_instance
import json
from stix_shifter_utils.utils.error_response import ErrorResponder
import time

ERROR_TYPE_TIMEOUT = 'timeout'
ERROR_TYPE_BAD_CONNECTION = 'bad_connection'

class UnexpectedResponseException(Exception):
    pass


class Connector(BaseSyncConnector):
    def __init__(self, connection, configuration):
        self.connection = connection
        self.configuration = configuration
        self.timeout = connection['options'].get('timeout')
        self.bundle_url = self.connection.get('url')
        auth = None
        conf_auth = configuration.get('auth', {})
        if 'username' in conf_auth and 'password' in conf_auth:
            auth = (conf_auth['username'], conf_auth['password'])
        self.client = RestApiClient(None,
                                    auth=auth,
                                    url_modifier_function=lambda host_port, endpoint, headers: f'{endpoint}')

    # We re-implement this method so we can fetch all the "bindings", as their method only
    # returns the first for some reason
    def match(self, pattern, observed_data_sdos, verbose=False):
        compiled_pattern = Pattern(pattern)
        matcher = MatchListener(observed_data_sdos, verbose)
        compiled_pattern.walk(matcher)

        found_bindings = matcher.matched()

        matching_sdos = []
        if found_bindings:
            for binding in found_bindings:
                matches = [match for match in matcher.get_sdos_from_binding(binding) if match not in matching_sdos]
                matching_sdos.extend(matches)
        return matching_sdos

    def ping_connection(self):
        return_obj = {}

        response = self.client.call_api(self.bundle_url, 'head', timeout=self.timeout)
        response_txt = response.raise_for_status()

        if response.code == 200:
            return_obj['success'] = True
        elif response.code == 301:
            self.bundle_url = response.headers.get('Location')
            return self.ping_connection()
        else:
            ErrorResponder.fill_error(return_obj, response_txt, ['message'])
        return return_obj

    def create_results_connection(self, search_id, offset, length):
        observations = []
        return_obj = {}

        response = None
        if self.connection['options'].get('error_type') == ERROR_TYPE_TIMEOUT:
            # httpstat.us/200?sleep=60000 for slow connection that is valid
            response = self.client.call_api('https://httpstat.us/200?sleep=60000', 'get', timeout=self.timeout)
        elif self.connection['options'].get('error_type') == ERROR_TYPE_BAD_CONNECTION:
            # www.google.com:81 for a bad connection that will timeout
            response = self.client.call_api('https://www.google.com:81', 'get', timeout=self.timeout)
        else:
            response = self.client.call_api(self.bundle_url, 'get', timeout=self.timeout)
        if response.code != 200:
            response_txt = response.raise_for_status()
            if ErrorResponder.is_plain_string(response_txt):
                ErrorResponder.fill_error(return_obj, message=response_txt)
            elif ErrorResponder.is_json_string(response_txt):
                response_json = json.loads(response_txt)
                ErrorResponder.fill_error(return_obj, response_json, ['reason'])
            else:
                raise UnexpectedResponseException
        else:
            try:
                response_txt = response.read().decode('utf-8')
                bundle = json.loads(response_txt)

                if "stix_validator" in self.connection['options'] and self.connection['options'].get("stix_validator") is True:
                    results = validate_instance(bundle)

                    if results.is_valid is not True:
                        ErrorResponder.fill_error(return_obj,  message='Invalid Objects in STIX Bundle.')
                        return return_obj

                observations.extend(
                    obj
                    for obj in bundle["objects"]
                    if obj["type"] == "observed-data"
                )

                # Pattern match
                try:
                    results = self.match(search_id, observations, False)

                    return_obj['success'] = True
                    if len(results) != 0:
                        return_obj['data'] = results[int(offset):int(offset + length)]
                    else:
                        return_obj['data'] = []
                except Exception as ex:
                    ErrorResponder.fill_error(
                        return_obj, message=f'Object matching error: {str(ex)}'
                    )

            except Exception as ex:
                ErrorResponder.fill_error(
                    return_obj,
                    message=f'Invalid STIX bundle. Malformed JSON: {str(ex)}',
                )

        return return_obj

    def create_query_connection(self, query):
        return {"success": True, "search_id": query}

    def create_status_connection(self, search_id):
        return {"success": True, "status": "COMPLETED", "progress": 100}

    def delete_query_connection(self, search_id):
        return {'success': True}
