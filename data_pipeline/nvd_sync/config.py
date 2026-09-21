import os

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY")

MAX_RETRY = 3
BACKOFF = 2
TIMEOUT = 30
