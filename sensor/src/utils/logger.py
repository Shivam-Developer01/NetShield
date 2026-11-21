import logging
import sys
import re

class SecretRedactingFormatter(logging.Formatter):
    """
    Custom log formatter redacting credentials, tokens, and passwords.
    """
    SECRET_PATTERNS = [
        (re.compile(r'(password\s*[:=]\s*)[^\s,;&]+', re.IGNORECASE), r'\1[REDACTED]'),
        (re.compile(r'(token\s*[:=]\s*)[^\s,;&]+', re.IGNORECASE), r'\1[REDACTED]'),
        (re.compile(r'(secret\s*[:=]\s*)[^\s,;&]+', re.IGNORECASE), r'\1[REDACTED]'),
        (re.compile(r'(bearer\s+)[a-zA-Z0-9\._\-]+', re.IGNORECASE), r'\1[REDACTED]')
    ]

    def format(self, record):
        message = super().format(record)
        for pattern, replacement in self.SECRET_PATTERNS:
            message = pattern.sub(replacement, message)
        return message


def get_logger(name: str = "netshield-sensor", level_name: str = "INFO") -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    level = getattr(logging, level_name.upper(), logging.INFO)
    logger.setLevel(level)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)

    formatter = SecretRedactingFormatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger
