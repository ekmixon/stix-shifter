import importlib
import sys
import traceback
from stix_shifter_utils.stix_translation.src.utils.exceptions import DataMappingException, \
    UnsupportedDataSourceException, UnsupportedLanguageException
from stix_shifter_utils.utils.module_discovery import process_dialects
from stix_shifter_utils.utils.error_response import ErrorResponder
from stix_shifter_utils.utils.param_validator import param_validator
from stix_shifter_utils.utils import logger
from stix_shifter_utils.utils.logger import exception_to_string

RESULTS = 'results'
QUERY = 'query'
PARSE = 'parse'
MAPPING = 'mapping'
DIALECTS = 'dialects'
SUPPORTED_ATTRIBUTES = "supported_attributes"
MAPPING_ERROR = "Unable to map the following STIX objects and properties to data source fields:"
DEFAULT_DIALECT = 'default'


class StixTranslation:
    """
    StixShifter class - implements translations of stix data
    """

    def __init__(self):
        self.args = []
        self.logger = logger.set_logger(__name__)

    def translate(self, module, translate_type, data_source, data, options={}, recursion_limit=1000):
        """
        Translated queries to a specified format
        :param module: What module to use
        :type module: one of connector modules: 'qradar', 'dummy'
        :param translate_type: translation of a query or result set must be one of: 'parse', 'mapping' 'query', 'results'
        :type translate_type: str
        :param data: the data to translate
        :type data: str
        :param options: translation options { stix_validator: bool }
        :type options: dict
        :param recursion_limit: maximum depth of Python interpreter stack
        :type recursion_limit: int
        :return: translated results
        :rtype: str
        """

        module, dialects = process_dialects(module, options)
        try:
            try:
                connector_module = importlib.import_module("stix_shifter_modules." + module + ".entry_point")
            except Exception as ex:
                raise UnsupportedDataSourceException("{} is an unsupported data source.".format(module))
            try:
                validated_options = (
                    {}
                    if translate_type == DIALECTS
                    else param_validator(module, options, 'connection.options')
                )

                entry_point = connector_module.EntryPoint(options=validated_options)
            except Exception as ex:
                track = traceback.format_exc()
                self.logger.error(ex)
                self.logger.debug(track)
                raise

            if translate_type == DIALECTS:
                dialects = entry_point.get_dialects_full()
                return dialects

            if len(dialects) == 0:
                dialects = entry_point.get_dialects()
                language = validated_options['language']
            else:
                language = options.get('language')

            if translate_type == QUERY or translate_type == PARSE:
                # Increase the python recursion limit to allow ANTLR to parse large patterns
                current_recursion_limit = sys.getrecursionlimit()
                if current_recursion_limit < recursion_limit:
                    self.logger.debug("Changing Python recursion limit from {} to {}".format(current_recursion_limit, recursion_limit))
                    sys.setrecursionlimit(recursion_limit)

                if translate_type == QUERY:
                    # Carbon Black combines the mapping files into one JSON using process and binary keys.
                    # The query constructor has some logic around which of the two are used.
                    queries = []
                    unmapped_stix_collection = []
                    dialects_used = 0
                    for dialect in dialects:
                        query_translator = entry_point.get_query_translator(dialect)
                        if not language or language == query_translator.get_language():
                            dialects_used += 1
                            transform_result = entry_point.transform_query(dialect, data)
                            if 'async_call' in transform_result:
                                queries.append(transform_result)
                            else:
                                queries.extend(transform_result.get('queries', []))
                            unmapped_stix_collection.extend(transform_result.get('unmapped_attributes', []))
                    if not dialects_used:
                        raise UnsupportedLanguageException(language)
                    if not queries:
                        raise DataMappingException(
                            "{} {}".format(MAPPING_ERROR, unmapped_stix_collection)
                        )
                    return {'queries': queries}
                else:
                    return entry_point.parse_query(data)
            elif translate_type == RESULTS:
                # Converting data from the datasource to STIX objects
                return entry_point.translate_results(data_source, data)
            elif translate_type == MAPPING:
                mappings = entry_point.get_mapping()
                return mappings
            elif translate_type == SUPPORTED_ATTRIBUTES:
                # Return mapped STIX attributes supported by the data source
                result = {}
                for dialect in dialects:
                    query_translator = entry_point.get_query_translator(dialect)
                    result[dialect] = query_translator.map_data
                return {'supported_attributes': result}
            else:
                raise NotImplementedError('wrong parameter: ' + translate_type)
        except Exception as ex:
            self.logger.error('Caught exception: ' + str(ex) + " " + str(type(ex)))
            self.logger.debug(exception_to_string(ex))
            response = {}
            ErrorResponder.fill_error(response, message_struct={'exception': ex})
            return response
