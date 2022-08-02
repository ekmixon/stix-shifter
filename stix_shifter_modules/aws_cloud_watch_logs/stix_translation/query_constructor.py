from stix_shifter_utils.stix_translation.src.patterns.pattern_objects import ObservationExpression, ComparisonExpression, \
    ComparisonExpressionOperators, ComparisonComparators, Pattern, \
    CombinedComparisonExpression, CombinedObservationExpression, ObservationOperators, StartStopQualifier
from stix_shifter_utils.stix_translation.src.utils.transformers import TimestampToMilliseconds
from stix_shifter_utils.utils.file_helper import read_json
from datetime import datetime, timedelta
import os.path as path
import json
import re

PROTOCOL_LOOKUP_JSON_FILE = 'network_protocol_map.json'
MASTER_CONFIG_FILE = 'master_config.json'
TIMESTAMP_PATTERN = r"\d{4}(-\d{2}){2}T\d{2}(:\d{2}){2}(\.\d+)?Z"


class QueryStringPatternTranslator:
    # Change comparator values to match with supported data source operators
    comparator_lookup = {
        ComparisonExpressionOperators.And: "AND",
        ComparisonExpressionOperators.Or: "OR",
        ComparisonComparators.GreaterThan: ">",
        ComparisonComparators.GreaterThanOrEqual: ">=",
        ComparisonComparators.LessThan: "<",
        ComparisonComparators.LessThanOrEqual: "<=",
        ComparisonComparators.Equal: "=",
        ComparisonComparators.NotEqual: "!=",
        ComparisonComparators.Like: "LIKE",
        ComparisonComparators.In: "IN",
        ComparisonComparators.Matches: "LIKE",
        ComparisonComparators.IsSubSet: '',
        ObservationOperators.Or: 'OR',
        ObservationOperators.And: 'OR'
    }
    aws_query = "fields {fields}{stix_filter} {parse_filter}{logtype_filter} | filter ({filter_query})"

    def __init__(self, pattern: Pattern, data_model_mapper, time_range, options):
        self.options = options
        self.dmm = data_model_mapper
        self.pattern = pattern
        self._time_range = time_range
        self.log_type = self.dmm.dialect
        self._log_config_data = read_json(MASTER_CONFIG_FILE, self.options)
        self._protocol_lookup_needed = self.log_type in ['vpcflow']
        self._parse_statement = []
        self.qualified_queries = []
        self.time_range_lst = []
        self._parse_filter = ''
        self._parse_statement = {}
        self.logtype_filter = self._log_config_data[self.log_type].get('logtype_filter')
        self.translated = self.parse_expression(pattern)

    def build_parse_statement(self, parse_statement):
        """
        Parse statements for guardduty logs
        :param parse_statement: dict, from master config json file
        :return: None
        """
        if self.log_type != 'guardduty':
            return
        validate = []
        self._parse_statement = []
        for key, value in parse_statement.items():
            filter_string = " or strlen({validate}) > 0".format(validate=key)
            validate.append(filter_string)
            parse_str = value.split(' ')[1]
            parse_string = (
                " | parse {parse}".format(parse=value)
                if parse_str.startswith('/')
                else " | parse {parse} as {field}".format(parse=value, field=key)
            )

            self._parse_statement.append(parse_string)
        self._parse_filter = "source = 'aws.guardduty'" + ''.join(validate)

    def protocol_lookup(self, value):
        """
        Function for protocol number lookup
        :param value:str or list, protocol
        :return:str or list, protocol
        """
        value = value.values if hasattr(value, 'values') else value
        protocol_json = read_json(PROTOCOL_LOOKUP_JSON_FILE, self.options)
        return (
            [
                protocol_json.get(each_value.lower())
                for each_value in value
                if each_value.lower() in protocol_json
            ]
            if isinstance(value, list)
            else protocol_json.get(value.lower())
        )

    @staticmethod
    def _format_set(values) -> list:
        """
        Formatting list of values in the event of IN operation
        :param values: str
        :return: list
        """
        values = values.values if hasattr(values, 'values') else values
        return list(map("{}".format, values))

    @staticmethod
    def _format_matches(value) -> str:
        """
        Formatting value in the event of MATCHES operation
        encapsulating the value inside regex keyword
        :param value: str
        :return: str
        """
        return (
            [f'/{each}/' for each in value]
            if isinstance(value, list)
            else f'/{value}/'
        )

    @staticmethod
    def _format_equality(value) -> str:
        """
        Formatting value in the event of equality operation
        :param value: str
        :return: str
        """
        return value if isinstance(value, list) else f"{value}"

    @staticmethod
    def _format_like(value) -> str:
        """
        Formatting value in the event of LIKE operation
        :param value: str
        :return: str
        """
        # Replacing value with % to .* and _ to . for supporting Like comparator
        if not isinstance(value, list):
            compile_regex = re.compile(r'.*(\%|\_).*')
            if compile_regex.match(value):
                value = f"/(?i){value.replace('%', '.*').replace('_', '.')}/"
            else:
                value = f'/(?i){value}/'
        return value

    @staticmethod
    def _format_datetime(value) -> list:
        """
        Formating value in the event of value is datetime
        :param value: datetime value
        :return: list, timestamp in milliseconds or timestamp itself
        """
        transformer = TimestampToMilliseconds()
        values = value.values if hasattr(value, 'values') else [value]
        milli_secs_lst = list(map(transformer.transform, values))
        values = list(map(lambda x: f'{str(x)[:-3]}', milli_secs_lst))
        return values

    @staticmethod
    def _negate_comparison(comparison_string):
        return f"NOT ({comparison_string})"

    def _parse_mapped_fields(self, expression, value, comparator, mapped_fields_array):
        """
        Mapping the stix object property with their corresponding property, from stix logtype json will be used for
        mapping
        :param expression: expression object, ANTLR parsed expression object
        :param value: str
        :param comparator: str
        :param mapped_fields_array: list, attributes in from stix logtype json file
        :return: str, filter condition will be constructed
        """
        comparison_string = ""
        mapped_fields_count = len(mapped_fields_array)
        for mapped_field in mapped_fields_array:
            if expression.comparator == ComparisonComparators.In or isinstance(value, list):
                value_chk = all(bool(val.isdigit()) for val in value)
                comparison_string += (
                    "{mapped_field} {comparator} {value}".format(
                        mapped_field=mapped_field,
                        comparator=comparator,
                        value=f"'{value[0]}'" if len(value) == 1 else value,
                    )
                    if value_chk
                    else '({})'.format(
                        ' OR '.join(
                            map(
                                lambda x: "tolower({mapped_field}) "
                                "{comparator} tolower('{value}')".format(
                                    mapped_field=mapped_field,
                                    comparator='=',
                                    value=x,
                                ),
                                value,
                            )
                        )
                    )
                )

            elif expression.comparator == ComparisonComparators.IsSubSet:
                comparison_string += "isIpv4InSubnet({mapped_field},'{value}')".format(mapped_field=mapped_field,
                                                                                       value=value)
            elif expression.comparator in [ComparisonComparators.Like,
                                           ComparisonComparators.Matches] or value.isdigit():
                comparison_string += "{mapped_field} {comparator} {value}".format(
                    mapped_field=mapped_field,
                    comparator=comparator,
                    value=f"'{value}'" if value.isdigit() else value,
                )

            else:
                comparison_string += "tolower({mapped_field}) {comparator} tolower('{value}')".\
                        format(mapped_field=mapped_field, comparator=comparator, value=value)
            if (
                'parse_attributes' in self._log_config_data.get(self.log_type)
                and mapped_field
                in self._log_config_data.get(self.log_type)
                .get('parse_attributes')
                .keys()
            ):
                parse_attributes_from_config = self._log_config_data.get(self.log_type).get('parse_attributes').get(
                    mapped_field).get('parse_string')
                parse_value = parse_attributes_from_config
                self._parse_statement.update({mapped_field: parse_value})
            if mapped_fields_count > 1:
                comparison_string += " OR "
                mapped_fields_count -= 1
        return comparison_string

    def _parse_time_range(self, qualifier, time_range):
        """
        Format the input time range UTC timestamp to Unix time
        :param time_range: int, value available from main.py in options variable
        :return: str, format_string
        """
        format_string = ''
        try:
            compile_timestamp_regex = re.compile(TIMESTAMP_PATTERN)
            transformer = TimestampToMilliseconds()
            if qualifier and compile_timestamp_regex.search(qualifier):
                time_range_iterator = map(lambda x: int(transformer.transform(x.group())/1000),
                                          compile_timestamp_regex.finditer(qualifier))
            # Default time range Start time = Now - 5 minutes and Stop time  = Now
            else:
                stop_time = datetime.now()
                start_time = int(round((stop_time - timedelta(minutes=time_range)).timestamp()))
                stop_time = int(round(stop_time.timestamp()))
                time_range_iterator = [start_time, stop_time]
            self.time_range_lst.append(list(time_range_iterator))
            return format_string
        except (KeyError, IndexError, TypeError) as e:
            raise e

    @staticmethod
    def _lookup_comparison_operator(self, expression_operator):
        if expression_operator not in self.comparator_lookup:
            raise NotImplementedError(
                f"Comparison operator {expression_operator.name} unsupported for AWS CloudWatch logs adapter"
            )

        return self.comparator_lookup[expression_operator]

    def _parse_expression(self, expression, qualifier=None) -> str or None:
        """
        Complete formation of AWS query from ANTLR expression object
        :param expression: expression object, ANTLR parsed expression object
        :param qualifier: str, default in None
        :return: str, comparison string
        """
        if isinstance(expression, ComparisonExpression):  # Base Case
            comparison_string = self.__eval_comparison_exp(expression)
            return f"{comparison_string}"
        elif isinstance(expression, CombinedComparisonExpression):
            operator = self._lookup_comparison_operator(self, expression.operator)
            expression_01 = self._parse_expression(expression.expr1)
            expression_02 = self._parse_expression(expression.expr2)
            return (
                ""
                if not expression_01 or not expression_02
                else f"({expression_01}) {operator} ({expression_02})"
            )

        elif isinstance(expression, ObservationExpression):
            self.__eval_observation_exp(expression, qualifier)
            return None
        elif isinstance(expression, CombinedObservationExpression):
            self._parse_expression(expression.expr1, qualifier)
            self._parse_expression(expression.expr2, qualifier)
            return None
        elif isinstance(expression, StartStopQualifier):
            if hasattr(expression, 'observation_expression'):
                return self._parse_expression(getattr(expression, 'observation_expression'), expression.qualifier)
        elif isinstance(expression, Pattern):
            return "{expr}".format(expr=self._parse_expression(expression.expression))
        else:
            raise RuntimeError(
                f"Unknown Recursion Case for expression={expression}, type(expression)={type(expression)}"
            )

    def __eval_observation_exp(self, expression, qualifier):
        """
        Function for parsing observation expression value
        :param expression: expression object
        :param qualifier: qualifier
        :return: str
        """
        if filter_query := self._parse_expression(
            expression.comparison_expression, qualifier
        ):
            self._parse_time_range(qualifier, self._time_range)
            self.build_parse_statement(self._parse_statement)
            self.qualified_queries.append(
                self.aws_query.format(
                    fields=', '.join(
                        self._log_config_data.get(self.log_type).get(
                            'display_fields'
                        )
                    ),
                    filter_query=filter_query,
                    stix_filter=''.join(self._parse_statement)
                    if self._parse_statement
                    else '',
                    parse_filter=f'| filter {self._parse_filter}'
                    if self._parse_filter
                    else '',
                    logtype_filter=f'| filter {self.logtype_filter}'
                    if self.logtype_filter
                    else '',
                )
            )

            # Re-initialize parse statement for multiple observation
            self._parse_statement = {}

    def __eval_comparison_exp(self, expression):
        """
        Parsing comparison expression
        :param expression: expression object, ANTLR parsed expression object
        :return: str
        """
        # Resolve STIX Object Path to a field in the target Data Model
        stix_object, stix_field = expression.object_path.split(':')
        # Custom condition for protocol lookup if log type == 'vpcflow'
        if stix_field.lower() == 'protocols[*]':
            existing_protocol_value = expression.value
            if self._protocol_lookup_needed:
                value = self.protocol_lookup(expression.value)
                if (not value) or (isinstance(value, list) and None in value):
                    raise NotImplementedError(
                        f"Un-supported protocol '{expression.value}' for operation '{expression.comparator}' for aws '{path.basename(self.log_type)}' logs"
                    )

                expression.value = value
        mapped_fields_array = self.dmm.map_field(stix_object, stix_field)
        comparator = self._lookup_comparison_operator(self, expression.comparator)
        comparison_string = self.__eval_comparison_value(comparator, expression, mapped_fields_array, stix_field)
        if stix_field.lower() == 'protocols[*]':
            expression.value = existing_protocol_value
        if len(mapped_fields_array) > 1:
            # More than one data source field maps to the STIX attribute, so group comparisons together.
            grouped_comparison_string = f"({comparison_string})"
            comparison_string = grouped_comparison_string
        if expression.negated and comparison_string:
            comparison_string = self._negate_comparison(comparison_string)
        return comparison_string

    def __eval_comparison_value(self, comparator, expression, mapped_fields_array, stix_field):
        """
        Function for parsing comparison expression value
        :param comparator: str, comparator value
        :param expression: expression object, ANTLR parsed expression object
        :param mapped_fields_array: list, values available in from stix logtype json file
        :param stix_field: str, stix field
        :return: str, comparison string
        """
        if stix_field in ["start", "end"]:
            if expression.comparator not in [ComparisonComparators.Matches, ComparisonComparators.Like]:
                value = self._format_datetime(expression.value)
            else:
                raise NotImplementedError(
                    f"STIX field '{stix_field}' un-supported for LIKE and MATCHES operation"
                )

        elif expression.comparator == ComparisonComparators.Matches:
            value = self._format_matches(expression.value)
        elif expression.comparator == ComparisonComparators.In:
            value = self._format_set(expression.value)
        elif expression.comparator in [
            ComparisonComparators.Equal,
            ComparisonComparators.NotEqual,
        ]:
            value = self._format_equality(expression.value)
        elif expression.comparator == ComparisonComparators.Like:
            value = self._format_like(expression.value)
        else:
            value = f'{expression.value}'
        return self._parse_mapped_fields(
            expression, value, comparator, mapped_fields_array
        )

    def parse_expression(self, pattern: Pattern):
        return self._parse_expression(pattern)


def translate_pattern(pattern: Pattern, data_model_mapping, options):
    """
    Conversion of expression object to AWS query
    :param pattern: expression object, ANTLR parsed expression object
    :param data_model_mapping: DataMapper object, mapping object obtained by parsing json
    :param options: dict, time_range defaults to 5
    :return: str, AWS query
    """
    time_range = options['time_range']
    limit = options['result_limit']
    final_queries = []
    queries_obj = QueryStringPatternTranslator(pattern, data_model_mapping, time_range, options)
    qualifier_list = list(zip(*queries_obj.time_range_lst))
    queries_string = queries_obj.qualified_queries
    for index, each_query in enumerate(queries_string, start=0):
        translate_query_dict = {
            'logType': queries_obj.log_type,
            'limit': limit,
            'queryString': each_query,
            'startTime': qualifier_list[0][index],
            'endTime': qualifier_list[1][index],
        }

        translate_query_dict = json.dumps(translate_query_dict)
        final_queries.append(translate_query_dict)
    return final_queries
