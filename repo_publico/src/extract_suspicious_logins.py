"""
This script extracts login activities from the Google Admin Reports API and identifies suspicious logins based on certain criteria.

It retrieves login activities for a specified date range and checks each activity against defined rules to determine if it is suspicious. The results are printed to the console.

To use this script, ensure you have the necessary API credentials and permissions to access the Google Admin Reports API. You can customize the `is_suspicious` function to implement your specific logic for identifying suspicious logins, such as checking for logins from unusual locations, devices, or times.

Make sure to install the required libraries, such as `google-api-python-client` and `google-auth`, before running the script.

Note: This script is a template and may require modifications to fit your specific use case and environment setup.
"""

from pathlib import Path
from dotenv import load_dotenv
from google.oauth2 import service_account
from googleapiclient.discovery import build
import ipaddress
import csv
import hashlib
import os
from functions import getGeoFromPI


BASE_DIR = Path(__file__).resolve().parents[1]
load_dotenv(BASE_DIR / '.env')

# Define the scopes and load environment variables
SCOPES = ['https://www.googleapis.com/auth/admin.reports.audit.readonly']

# SERVICE_ACCOUNT_FILE = os.getenv('GOOGLE_APPLICATION_CREDENTIALS')
SERVICE_ACCOUNT_FILE = BASE_DIR / "credentials.json" 
DELEGATED_ADMIN = os.getenv('GOOGLE_WORKSPACE_ADMIN')
START_TIME = os.getenv('START_TIME')
END_TIME = os.getenv('END_TIME')
MAX_RESULTS = int(os.getenv('MAX_RESULTS', 20))
OUTPUT_FILE = BASE_DIR / os.getenv('OUTPUT_FILE', 'data/raw/suspicious_logins.csv')


# Ensure that the required environment variables are set
if not SERVICE_ACCOUNT_FILE or not DELEGATED_ADMIN:
    raise ValueError("Please set the GOOGLE_APPLICATION_CREDENTIALS and GOOGLE_WORKSPACE_ADMIN environment variables.")

# Authenticate and build the service
api_credentials = service_account.Credentials.from_service_account_file(
    SERVICE_ACCOUNT_FILE, 
    scopes=SCOPES
    ).with_subject(DELEGATED_ADMIN)

# Build the service object for the Admin Reports API
service = build('admin', 'reports_v1', credentials=api_credentials)


fields = [
    "record_id",
    "event_time",
    "actor_email_hash",
    "ip_hash",
    "ip_version",
    "ip_country",
    "ip_region",
    "ip_city",
    "continent",
    'latitude',
    'longitude',
    "event_name",
    "is_suspicious",
    "login_type",
    "login_challenge_method",
    # Extra
    "login_status"
]


# Function to extract the value from a parameter, handling different types
def get_param_value(param):
    if "value" in param:
        return param["value"]
    if "boolValue" in param:
        return param["boolValue"]
    if "intValue" in param:
        return param["intValue"]
    if "multiValue" in param:
        return param["multiValue"]
    if "multiStrValue" in param:
        return param["multiStrValue"]
    return None

# Function to detect IP version
def detect_ip_version(ip_value):
    try:
        return ipaddress.ip_address(ip_value).version
    except Exception:
        return None

# Function to hash sensitive information
def h(v: str) -> str:
    return hashlib.sha256(v.encode('utf-8')).hexdigest()[:16] if v else None

# Function to safely hash values, returning None for empty or None values
def safe_hash(value):
    return h(str(value)) if value not in (None, "") else None



def flatten (item, record_id):
    
    id_obj = item.get("id", {})
    actor_obj = item.get("actor", {})
    geo_obj = item.get("geoLocation", {})
    events = item.get("events", [])
    raw_ip = item.get("ipAddress", "")
    geo_fallback = getGeoFromPI(raw_ip)
    
    row = {
        "record_id": record_id,
        # id
        "event_time": id_obj.get("time"),
        # actor
        "actor_email_hash": safe_hash(actor_obj.get("email")),
      
        # Network / geolocation
        "ip_hash": safe_hash(raw_ip),
        "ip_country": geo_obj.get("country") or geo_fallback["ip_country"],
        "ip_region": geo_obj.get("region") or geo_fallback["ip_region"],
        "ip_city": geo_obj.get("city") or geo_fallback["ip_city"],
        "continent": geo_obj.get("continent") or geo_fallback["continent"],
        "ip_version": geo_fallback["ip_version"],
        "latitude": geo_fallback["latitude"],
        "longitude": geo_fallback["longitude"],

        # events
        "event_name": None,
        
        # login-specific fields
        "is_suspicious": None,
        "login_type": None,
        "login_challenge_method": None,
        # Extra fields
        "login_status": None
    }

   

    for ev in events:
        
        if row["event_name"] is None:
            event_name = ev.get("name")
            row["event_name"] = event_name
            # extra add
            if event_name == "login_success":
                row["login_status"] = "success"
            elif event_name == "login_failure":
                row["login_status"] = "failure"
            elif event_name == "login_challenge":
                row["login_status"] = "challenge"
            elif event_name == "login_verification":
                row["login_status"] = "verification"
            else:
                row["login_status"] = "other"
         
         
        for param in ev.get("parameters", []):
            name = param.get("name")
            value = get_param_value(param)
            
            if name == "ip_address":
                row["ip_hash"] = safe_hash(value)

            elif name == "is_suspicious":
                row["is_suspicious"] = value

            elif name == "login_type":
                row["login_type"] = value

            elif name == "login_challenge_method":
                if isinstance(value, list):
                    row["login_challenge_method"] = "|".join(map(str, value))
                else:
                    row["login_challenge_method"] = value
    return row
  
  
rows = []
page_token = None
record_id = 1

while True:
    response = service.activities().list(
        userKey='all',
        applicationName='login',
        startTime=START_TIME,
        endTime=END_TIME,
        eventName='login_success',
        #filters='is_suspicious==true',
        maxResults=MAX_RESULTS,
        pageToken=page_token,
    ).execute()

    items = response.get('items', [])
    for item in items:
        rows.append(flatten(item, record_id))
        record_id += 1

    page_token = response.get('nextPageToken')
    if not page_token:
        break
        
# Save the results to a CSV file
with open(OUTPUT_FILE, 'w', newline='', encoding='utf-8') as f:
    writer = csv.DictWriter(f, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)

# Print summary
print(f'File saved in: {OUTPUT_FILE}')
print(f'Records: {len(rows)}')
