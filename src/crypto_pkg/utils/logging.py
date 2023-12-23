import logging

from crypto_pkg import settings


def get_logger(location: str = __name__):
    log = logging.getLogger(location)
    log.setLevel(settings.log_level)
    return log


def set_level(logger):
    def deco(func):
        def wrapper( *args, **kwargs):
            if kwargs.get('verbose') and kwargs.get('verbose') is True:
                logger.setLevel(logging.DEBUG)
            return func(*args, **kwargs)
        return wrapper

    return deco
