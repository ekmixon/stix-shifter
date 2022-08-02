from stix_shifter_utils.stix_translation.src.patterns.pattern_objects import ObservationExpression, ComparisonExpression, \
    ComparisonExpressionOperators, ComparisonComparators, Pattern, \
    CombinedComparisonExpression, CombinedObservationExpression, ObservationOperators
from stix_shifter_utils.stix_translation.src.utils.transformers import TimestampToMilliseconds
from stix_shifter_utils.stix_translation.src.json_to_stix import observable
import logging
import re

# Source and destination reference mapping for ip and mac addresses.
# Change the keys to match the data source fields. The value array indicates the possible data type that can come into from field.
REFERENCE_DATA_TYPES = {"SourceIpV4": ["ipv4", "ipv4_cidr"],
                        "SourceIpV6": ["ipv6"],
                        "DestinationIpV4": ["ipv4", "ipv4_cidr"],
                        "DestinationIpV6": ["ipv6"]}

logger = logging.getLogger(__name__)


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
        ComparisonComparators.Matches: 'LIKE',
        # ComparisonComparators.IsSubSet: '',
        # ComparisonComparators.IsSuperSet: '',
        ObservationOperators.Or: 'OR',
        # Treat AND's as OR's -- Unsure how two ObsExps wouldn't cancel each other out.
        ObservationOperators.And: 'OR'
    }

    def __init__(self, pattern: Pattern, data_model_mapper):
        self.dmm = data_model_mapper
        self.pattern = pattern
        self.translated = self.parse_expression(pattern)

    @staticmethod
    def _format_set(values) -> str:
        gen = values.element_iterator()
        return f"({' OR '.join([QueryStringPatternTranslator._escape_value(value) for value in gen])})"

    @staticmethod
    def _format_match(value) -> str:
        raw = QueryStringPatternTranslator._escape_value(value)
        raw = raw[1:] if raw[0] == "^" else f".*{raw}"
        raw = raw[:-1] if raw[-1] == "$" else f"{raw}.*"
        return f"\'{raw}\'"

    @staticmethod
    def _format_equality(value) -> str:
        return f"\'{value}\'"

    @staticmethod
    def _format_like(value) -> str:
        value = "'%{value}%'".format(value=value)
        return QueryStringPatternTranslator._escape_value(value)

    @staticmethod
    def _escape_value(value, comparator=None) -> str:
        if isinstance(value, str):
            return '{}'.format(value.replace('\\', '\\\\').replace('\"', '\\"').replace('(', '\\(').replace(')', '\\)'))
        else:
            return value

    @staticmethod
    def _negate_comparison(comparison_string):
        return f"NOT ({comparison_string})"

    @staticmethod
    def _check_value_type(value):
        value = str(value)
        return next(
            (
                key
                for key, pattern in observable.REGEX.items()
                if key != 'date' and bool(re.search(pattern, value))
            ),
            None,
        )

    #TODO remove self reference from static methods
    @staticmethod
    def _parse_reference(self, stix_field, value_type, mapped_field, value, comparator):
        if value_type not in REFERENCE_DATA_TYPES[f"{mapped_field}"]:
            return None
        else:
            return "{mapped_field} {comparator} {value}".format(
                mapped_field=mapped_field, comparator=comparator, value=value)

    @staticmethod
    def _parse_mapped_fields(self, expression, value, comparator, stix_field, mapped_fields_array):
        comparison_string = ""
        is_reference_value = self._is_reference_value(stix_field)
        # Need to use expression.value to match against regex since the passed-in value has already been formated.
        value_type = self._check_value_type(expression.value) if is_reference_value else None
        mapped_fields_count = 1 if is_reference_value else len(mapped_fields_array)

        for mapped_field in mapped_fields_array:
            if is_reference_value:
                if parsed_reference := self._parse_reference(
                    self, stix_field, value_type, mapped_field, value, comparator
                ):
                    comparison_string += parsed_reference
                else:
                    continue
            else:
                comparison_string += "{mapped_field} {comparator} {value}".format(mapped_field=mapped_field, comparator=comparator, value=value)

            if (mapped_fields_count > 1):
                comparison_string += " OR "
                mapped_fields_count -= 1
        return comparison_string

    @staticmethod
    def _is_reference_value(stix_field):
        return stix_field in ['src_ref.value', 'dst_ref.value']

    @staticmethod
    def _lookup_comparison_operator(self, expression_operator):
        if expression_operator not in self.comparator_lookup:
            raise NotImplementedError(
                f"Comparison operator {expression_operator.name} unsupported for Dummy connector"
            )

        return self.comparator_lookup[expression_operator]

    def _parse_expression(self, expression, qualifier=None) -> str:
        if isinstance(expression, ComparisonExpression):  # Base Case
            # Resolve STIX Object Path to a field in the target Data Model
            stix_object, stix_field = expression.object_path.split(':')
            # Multiple data source fields may map to the same STIX Object
            mapped_fields_array = self.dmm.map_field(stix_object, stix_field)
            # Resolve the comparison symbol to use in the query string (usually just ':')
            comparator = self._lookup_comparison_operator(self, expression.comparator)

            if stix_field in ['start', 'end']:
                transformer = TimestampToMilliseconds()
                expression.value = transformer.transform(expression.value)

            # Some values are formatted differently based on how they're being compared
            if expression.comparator == ComparisonComparators.Matches:  # needs forward slashes
                value = self._format_match(expression.value)
            elif expression.comparator == ComparisonComparators.In:
                value = self._format_set(expression.value)
            elif expression.comparator in [
                ComparisonComparators.Equal,
                ComparisonComparators.NotEqual,
            ]:
                # Should be in single-quotes
                value = self._format_equality(expression.value)
            elif expression.comparator == ComparisonComparators.Like:
                value = self._format_like(expression.value)
            else:
                value = self._escape_value(expression.value)

            comparison_string = self._parse_mapped_fields(self, expression, value, comparator, stix_field, mapped_fields_array)
            if (len(mapped_fields_array) > 1 and not self._is_reference_value(stix_field)):
                # More than one data source field maps to the STIX attribute, so group comparisons together.
                grouped_comparison_string = f"({comparison_string})"
                comparison_string = grouped_comparison_string

            if expression.negated:
                comparison_string = self._negate_comparison(comparison_string)
            if qualifier is not None:
                return f"{comparison_string} {qualifier}"
            else:
                return f"{comparison_string}"

        elif isinstance(expression, CombinedComparisonExpression):
            operator = self._lookup_comparison_operator(self, expression.operator)
            expression_01 = self._parse_expression(expression.expr1)
            expression_02 = self._parse_expression(expression.expr2)
            if not expression_01 or not expression_02:
                return ''
            if isinstance(expression.expr1, CombinedComparisonExpression):
                expression_01 = f"({expression_01})"
            if isinstance(expression.expr2, CombinedComparisonExpression):
                expression_02 = f"({expression_02})"
            query_string = f"{expression_01} {operator} {expression_02}"
            if qualifier is not None:
                return f"{query_string} {qualifier}"
            else:
                return f"{query_string}"
        elif isinstance(expression, ObservationExpression):
            return self._parse_expression(expression.comparison_expression, qualifier)
        elif hasattr(expression, 'qualifier') and hasattr(expression, 'observation_expression'):
            if not isinstance(
                expression.observation_expression, CombinedObservationExpression
            ):
                return self._parse_expression(expression.observation_expression.comparison_expression, expression.qualifier)
            operator = self._lookup_comparison_operator(self, expression.observation_expression.operator)
            expression_01 = self._parse_expression(expression.observation_expression.expr1)
            # qualifier only needs to be passed into the parse expression once since it will be the same for both expressions
            expression_02 = self._parse_expression(expression.observation_expression.expr2, expression.qualifier)
            return f"{expression_01} {operator} {expression_02}"
        elif isinstance(expression, CombinedObservationExpression):
            operator = self._lookup_comparison_operator(self, expression.operator)
            expression_01 = self._parse_expression(expression.expr1)
            expression_02 = self._parse_expression(expression.expr2)
            if expression_01 and expression_02:
                return f"({expression_01}) {operator} ({expression_02})"
            elif expression_01:
                return f"{expression_01}"
            elif expression_02:
                return f"{expression_02}"
            else:
                return ''
        elif isinstance(expression, Pattern):
            return "{expr}".format(expr=self._parse_expression(expression.expression))
        else:
            raise RuntimeError(
                f"Unknown Recursion Case for expression={expression}, type(expression)={type(expression)}"
            )

    def parse_expression(self, pattern: Pattern):
        return self._parse_expression(pattern)


def translate_pattern(pattern: Pattern, data_model_mapping, options):
    # result_limit = options['result_limit']
    # time_range = options['time_range']
    query = QueryStringPatternTranslator(pattern, data_model_mapping).translated
    query_split = query.split(" START")
    if len(query_split) > 1:
        query_time = query_split[1].replace("t'","")
        time = query_time.split("STOP")
        start_time = time[0].replace("T"," ").replace("Z'","")
        stop_time = time[1].replace("T"," ").replace("Z'","")
        time_interval = " AND a.timeCollr BETWEEN '" + start_time + "' AND '" + stop_time + "'"
        query = query_split[0] + time_interval

    # Return a statement in a pseudo SQL format, that will be executed on the Alertflex controller side.
    query = [f"SELECT a FROM Alert a WHERE {query}"]
    return query
