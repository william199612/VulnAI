import re

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

MAX_RETRIES = 5
TIMEOUT = (10, 60)
