from stix_shifter_utils.stix_translation.src.patterns.pattern_objects import \
    ObservationExpression, ComparisonExpression, \
    ComparisonExpressionOperators, ComparisonComparators, Pattern, \
    CombinedComparisonExpression, CombinedObservationExpression, \
    ObservationOperators

import logging
import re
import dateutil.parser

from datetime import datetime as dtime
from datetime import timedelta
from json import dumps

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
        ComparisonComparators.Matches: 'MATCHES',
        ComparisonComparators.IsSubSet: 'INCIDR',
        ObservationOperators.Or: 'OR',
        # Treat AND's as OR's -- Unsure how two ObsExps wouldn't cancel each other out.
        ObservationOperators.And: 'OR'
    }

    def __init__(self, pattern: Pattern, data_model_mapper):
        self.dmm = data_model_mapper
        self.pattern = pattern
        self.translated = self.parse_expression(pattern)

    def ipFilter(self, field, comparison, val):
        if comparison == ComparisonComparators.Equal:
            return {field: [{"Cidr": val}]}
        else:
            raise RuntimeError(f"Unsupported comparison for IP {comparison}")

    def numberFilter(self, field, comparison, val):
        if comparison == ComparisonComparators.Equal:
            return {field: [{"Eq": val}]}
        elif comparison == ComparisonComparators.NotEqual:
            return {field: [{"Gte": val + 1}, {"Lte": val - 1}]}
        elif comparison == ComparisonComparators.LessThanOrEqual:
            return {field: [{"Lte": val}]}
        elif comparison == ComparisonComparators.LessThan:
            return {field: [{"Lte": val - 1}]}
        elif comparison == ComparisonComparators.GreaterThanOrEqual:
            return {field: [{"Gte": val}]}
        elif comparison == ComparisonComparators.GreaterThan:
            return {field: [{"Gte": val + 1}]}
        else:
            raise RuntimeError(f"Unsupported comparison for numeric {comparison}")

    def dateFilter(self, field, comparison, val):
        dt = dateutil.parser.parse(val)
        before = (dt - timedelta(seconds=1)).isoformat()
        after = (dt + timedelta(seconds=1)).isoformat()
        forever = dtime.fromtimestamp(2147483647).isoformat()
        never = dtime.fromtimestamp(0).isoformat()

        if comparison == ComparisonComparators.Equal:
            return {field: [{"Start": val, "End": val}]}
        elif comparison == ComparisonComparators.NotEqual:
            return {field: [{"Start": never, "End": before}, {"Start": after, "End": forever}]}
        elif comparison == ComparisonComparators.LessThanOrEqual:
            return {field: [{"Start": never, "End": val}]}
        elif comparison == ComparisonComparators.LessThan:
            return {field: [{"Start": never, "End": before}]}
        elif comparison == ComparisonComparators.GreaterThanOrEqual:
            return {field: [{"Start": val, "End": forever}]}
        elif comparison == ComparisonComparators.GreaterThan:
            return {field: [{"Start": after, "End": forever}]}
        else:
            raise RuntimeError(f"Unsupported comparison for date {comparison}")

    def stringFilter(self, field, comparison, val):
        if comparison == ComparisonComparators.Equal:
            return {field: [{"Comparison": "EQUALS", "Value": val}]}
        elif comparison == ComparisonComparators.Like:
            return {field: [{"Comparison": "CONTAINS", "Value": val.replace("%", "")}]}
        else:
            raise RuntimeError(f"Unsupported comparison for string {comparison}")

    def _parse_expression(self, expression, qualifier=None) -> str:
        filters = []

        if isinstance(expression, ComparisonExpression):  # Base Case
            # [ a:foo = x ]
            # Resolve STIX Object Path to a field in the target Data Model
            stix_object, stix_field = expression.object_path.split(':')
            # Multiple data source fields may map to the same STIX Object
            mapped_fields_array = self.dmm.map_field(stix_object, stix_field)
            # Resolve the comparison symbol to use in the query string (usually just ':')
            comparator = self.comparator_lookup[expression.comparator]

            filterTypes = {
                "NetworkSourceIpV4": self.ipFilter,
                "NetworkDestinationIpV4": self.ipFilter,
                "NetworkSourceIpV6": self.ipFilter,
                "NetworkDestinationIpV6": self.ipFilter,
                "NetworkSourceDomain": self.stringFilter,
                "NetworkSourcePort": self.numberFilter,
                "NetworkDestinationPort": self.numberFilter,
                "ResourceAwsIamAccessKeyUserName": self.stringFilter,
                "FirstObservedAt": self.dateFilter,
                "LastObservedAt": self.dateFilter,
                "CreatedAt": self.dateFilter
            }

            mapped_field = mapped_fields_array[0]
            filterObject = filterTypes.get(
                mapped_field,
                lambda a, b: f"Unsupported filter type {mapped_field}",
            )

            filter = filterObject(mapped_field, expression.comparator, expression.value)

            if len(mapped_fields_array) > 1:
                filter['orlist'] = []
                for i in range(1, len(mapped_fields_array)):
                    mapped_field = mapped_fields_array[i]
                    filterObject = filterTypes.get(
                        mapped_field,
                        lambda a, b: f"Unsupported filter type {mapped_field}",
                    )

                    filter['orlist'].append(filterObject(
                        mapped_field, expression.comparator, expression.value))

            filters.append(filter)

            if qualifier is not None:
                if m := re.search(
                    "STARTt('\\d{4}(-\\d{2}){2}T\\d{2}(:\\d{2}){2}(\\.\\d+)?Z')STOPt('\\d{4}(-\\d{2}){2}T\\d{2}(:\\d{2}){2}(\\.\\d+)?Z')",
                    qualifier,
                ):
                    filters.extend(
                        (
                            self.dateFilter(
                                "FirstObservedAt",
                                ComparisonComparators.GreaterThanOrEqual,
                                m[1],
                            ),
                            self.dateFilter(
                                "LastObservedAt",
                                ComparisonComparators.LessThan,
                                m[2],
                            ),
                        )
                    )

                else:
                    raise RuntimeError(f"Qualifier {dumps(qualifier)} is not currently supported")

            return filters

        elif isinstance(
            expression,
            (CombinedComparisonExpression, CombinedObservationExpression),
        ):
            # [ a:foo = x AND b:foo = y ]
            comparator = self.comparator_lookup[expression.operator]
            if comparator in [
                ComparisonExpressionOperators.Or,
                ObservationOperators.Or,
            ]:
                raise RuntimeError("\"OR\" comparisons are not currently supported")

            filters.extend(
                (
                    self._parse_expression(expression.expr1),
                    self._parse_expression(expression.expr2),
                )
            )

            if qualifier is not None:
                if m := re.search(
                    "STARTt('\\d{4}(-\\d{2}){2}T\\d{2}(:\\d{2}){2}(\\.\\d+)?Z')STOPt('\\d{4}(-\\d{2}){2}T\\d{2}(:\\d{2}){2}(\\.\\d+)?Z')",
                    qualifier,
                ):
                    filters.extend(
                        (
                            self.dateFilter(
                                "FirstObservedAt",
                                ComparisonComparators.GreaterThanOrEqual,
                                m[1],
                            ),
                            self.dateFilter(
                                "LastObservedAt",
                                ComparisonComparators.LessThan,
                                m[2],
                            ),
                        )
                    )

                else:
                    raise RuntimeError(f"Qualifier {dumps(qualifier)} is not currently supported")
            return filters

        elif isinstance(expression, ObservationExpression):
            # [ a:foo = x AND b:foo = y ]
            return self._parse_expression(expression.comparison_expression, qualifier)
        elif hasattr(expression, 'qualifier') and hasattr(expression, 'observation_expression'):
            if not isinstance(
                expression.observation_expression, CombinedObservationExpression
            ):
                return self._parse_expression(
                    expression.observation_expression.comparison_expression,
                    expression.qualifier
                )

            comparator = self.comparator_lookup[expression.observation_expression.operator]
            if comparator == ObservationOperators.Or:
                raise RuntimeError("\"OR\" comparisons are not currently supported")

            filters.extend(
                (
                    self._parse_expression(
                        expression.observation_expression.expr1
                    ),
                    self._parse_expression(
                        expression.observation_expression.expr2
                    ),
                )
            )

            return filters
        elif isinstance(expression, Pattern):
            return self._parse_expression(expression.expression)
        else:
            raise RuntimeError(
                f"Unknown Recursion Case for expression={expression}, type(expression)={type(expression)}"
            )

    def parse_expression(self, pattern: Pattern):
        return self._parse_expression(pattern)


def filtersToQueries(filters):
    queries = []
    filterObject = {}

    for i in range(len(filters)):
        filter = filters[i]
        if 'orlist' in filter:

            for orFilter in filter['orlist']:
                newFilters = filters.copy()
                del newFilters[i]
                newFilters.append(orFilter)
                queries = queries + filtersToQueries(newFilters)

            del filter['orlist']

        filterField = next(iter(filter))
        filterObject[filterField] = filter[filterField]

    queries.append(dumps(filterObject))

    return queries


def translate_pattern(pattern: Pattern, data_model_mapping):
    filters = QueryStringPatternTranslator(pattern, data_model_mapping) \
        .translated

    return filtersToQueries(filters)
