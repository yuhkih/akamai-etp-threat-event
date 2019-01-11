# ----------------------------------------
#  Name: etp_threat_event.py
#  Purpose: Sample cord to get threat events from ETP server.
#  2019/01/08 yuhki initial relase using "Enterprise Threat Protector Reporting API v1"
#                   verified with Python 3.6.3 and 2.7.14 on Windows 10
#  2019/01/11 yuhki change display time zone from GMT to Local time (gmtime() → localtime() )
#                   change the first request duration to the past 7 days. (when there is no timestamp file)
# ----------------------------------------

import requests
from akamai.edgegrid import EdgeGridAuth
import time
from datetime import datetime
import json
import os

# ----------------------------------------
# User Preferences
# ----------------------------------------
CustomerId = "xxxx"  # Please go "Utilities" -> "Client Connector Tab". You can find your Customer Id on the left.
if CustomerId == "xxxx":
    print("Please open this script and set CustomerId to your Customer ID")
    exit()
# Output format Settings
format_json = 0 # (CSV=0, JSON=1)
duration_days = 7 # request duration in day from now. If 2, it means the last 48 hours.
DEBUG = 0 # 0 or 1(DEBUG)

def debug_result(response, action):
    print("[DEBUG] ----- Request Header -----")
    print(response.request.headers)
    print("[DEBUG] ----- Response Code -----")
    print(response.status_code)
    print("[DEBUG] ----- Response Header -----")
    print(response.headers)
    if action != 'download':
        print("[DEBUG] ----- Response Content -----")
        print(response.text)


# ----------------------------------------
# Open a credential file
# It is assumed that you use a credential file dwonloaded from LUNA portal as is.
# When you download the credntial file from LUNA. The format is like below. (space separated)
# ------- (These values are dummy) -------
# Please insert space as a sperator
# client_secret = 1Ul0WtarfadfgfgafgPo2XRmAsbPbzjw=
# host = akab-jza67c2hm2atagfasfgsafgurr67wf.luna.akamaiapis.net
# access_token = akab-ape6fgagfayrafa-532hlfdttj2sxxq6
# client_token = akab-ruu3utadfasrfdn-elmvfqhpi5l6oezf
# ----------------------------------------

# Check if a credential file exists
credential_file = "./credential.txt"
if os.path.exists(credential_file):
    file = open('credential.txt','r')
    lines = file.readlines()
    file.close
else:
    print("[ERROR]Please download a credential file from LUNA and name it credential.txt and place it in the same directory")
    exit()


# Read the credential.txt
for line in lines:
    if line.find("client_secret") >=0:
        client_secret = line[:-1].split(" ")[2]
        sclient_secret='client_secret=' + client_secret
    if line.find("host") >=0:
        host = line[:-1].split(" ")[2]
        shost='host=' + host
    if line.find("access_token") >=0:
        access_token = line[:-1].split(" ")[2]
        saccess_token = "access_token=" + access_token
    if line.find("client_token") >=0:
        client_token = line[:-1].split(" ")[2]
        sclient_token = "client_token=" + client_token

# ----------------------------------------
# For Debug. Print Credential file 
# ----------------------------------------
if DEBUG == 1:
    print("=====  Credential File  ======")
    print(sclient_secret)
    print(shost)
    print(saccess_token)
    print (sclient_token)
    print("=============================")

# ----------------------------------------
# Prepare needed for HTTP request
# ----------------------------------------
baseurl = 'https://' + host
s = requests.Session()
s.auth = EdgeGridAuth(
client_token,
client_secret,
access_token
)

if format_json:
   headers = {'Accept': 'application/json'}  # Just in case. Seems not care
else:
  headers = {'Accept': 'text/csv'}

# Create Start and End time
now = datetime.now()
end_e = int(time.mktime(now.timetuple())) # End Epoch time. Need to cast into integer to remove decimal point
  
# If there is a former_end_time.txt, read it
path = "./former_end_time.txt"

if os.path.exists(path):
  file = open('former_end_time.txt','r')
  former_end_e = file.read()
  file.close()  

  if len(former_end_e) == 0:
     os.remove(path)
  else:    
    start_e = int(former_end_e) + 1   # new start epoch time
    
else:
  number = 86400 * duration_days       # 24 hours 
  start_e = end_e - number             # Start Epoch time. 

# write end time into a file (end_time.txt)
file = open('former_end_time.txt','w') # overwrite
file.write(str(end_e))
file.close()

# Threat event request duration Message
message = "[MSG] Querying threat events from " + time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(start_e)) + " to " +  time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(end_e))
print(message)

# ----------------------------------------
# Execute API Request
# ----------------------------------------
filters=''  # No Filter
request_url = baseurl + "/etp-report/v1/configs/" + CustomerId + "/threat-events/details?startTimeSec=" + str(start_e) + '&endTimeSec=' + str(end_e) + '&filters=' + filters
result = s.get(request_url,headers=headers)

# ---------------------------------------- 
# Print result
# ----------------------------------------
if DEBUG == 1:
    print("HTTP Response Code:" + str(result.status_code))  # status code
    print(result.request.headers)

if format_json :
    print(json.dumps(result.json(),indent=2))
else:
    print(result.text)