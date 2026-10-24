import os

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.getenv("NVD_API_KEY")

MAX_RETRIES = 5
TIMEOUT = (10, 60)
