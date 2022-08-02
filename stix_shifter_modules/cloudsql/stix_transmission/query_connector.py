from stix_shifter_utils.modules.base.stix_transmission.base_connector import BaseQueryConnector
import json


class QueryConnector(BaseQueryConnector):
    def __init__(self, api_client):
        self.api_client = api_client

    def create_query_connection(self, query):
        q = json.loads(query)["query"]
        # Grab the response, extract the response code,
        # and convert it to readable json
        try:
            jobid = self.api_client.submit_sql(q)
        except SyntaxError as e:
            return_obj = {'success': False, 'error': repr(e)}
            return return_obj

        # Construct a response object
        return_obj = {'success': True, 'search_id': jobid}
        return return_obj
