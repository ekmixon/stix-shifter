import logging

from stix_shifter_utils.modules.base.stix_translation.base_query_translator import (
    BaseQueryTranslator
)

from . import query_constructor

logger = logging.getLogger(__name__)


class QueryTranslator(BaseQueryTranslator):

    def transform_antlr(self, data, antlr_parsing_object):
        logger.info("Converting STIX2 Pattern to data source query")
        return query_constructor.translate_pattern(
            antlr_parsing_object, self, self.options
        )
