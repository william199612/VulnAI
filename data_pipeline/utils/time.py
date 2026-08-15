from email.utils import parsedate_to_datetime
from datetime import datetime

def pub_date_to_ts(pub_date_str: str) -> int:
    dt = parsedate_to_datetime(pub_date_str)
    return int(dt.timestamp())