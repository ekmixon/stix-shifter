# -*- coding: utf-8 -*-
from datetime import datetime
from stix_shifter_utils.stix_translation.src.utils.transformers import ValueTransformer
from stix_shifter_utils.utils import logger

LOGGER = logger.set_logger(__name__)


class InfobloxToDomainName(ValueTransformer):
    """A value transformer for expected domain name"""

    @staticmethod
    def transform(url):
        return None if url is None else url.rstrip('.')

    @staticmethod
    def untransform(url):
        return None if url is None else f'{url}.'

class TimestampToSeconds(ValueTransformer):
    """
    A value transformer for converting a UTC timestamp (YYYY-MM-DDThh:mm:ss.000Z)
    to 10-digit Unix time (epoch + seconds)
    """

    @staticmethod
    def transform(timestamp):
        time_pattern = '%Y-%m-%dT%H:%M:%S.%fZ'
        epoch = datetime(1970, 1, 1)
        try:
            return int(
                (
                    (
                        datetime.strptime(timestamp, time_pattern) - epoch
                    ).total_seconds()
                )
            )

        except ValueError:
            LOGGER.error("Cannot convert the timestamp %s to seconds", timestamp)
        return None
