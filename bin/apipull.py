import requests
import json
import time
from ConfigParser import SafeConfigParser

#load configuration file
parser = SafeConfigParser()
parser.read('../local/protectwise.conf')
apiUrl = parser.get('protectwise','apiUrl')
header = {'Content-Type': 'application/json'}
payload = {"email": parser.get('protectwise','email'), "password": parser.get('protectwise','password')}
latest = int(time.time()*1000.0)
earliest = int(latest - 31556952000)
eventsUrl = apiUrl + "/events?"
evtParam = {'start': earliest, 'end': latest, 'maxlimit': '5'}



def genToken():
    getToken = requests.post(apiUrl+"/token", headers=header, data=json.dumps(payload))
    token = getToken.json()
    global aHeader
    aHeader = {'Content-Type': 'application/json', 'X-Access-Token': token[u'token']}

def getEvents():
    events = requests.get(eventsUrl, headers= aHeader, params= evtParam, stream=True)
    print(events.url)
    print(events.encoding)
    for line in events.iter_lines():
        # filter out keep-alive new lines
        if line:
            decoded_line = line.decode('utf-8')
            print(json.dumps(decoded_line))


tr = requests.get(eventsUrl, headers= header)
if tr.status_code  == requests.codes.unauthorized:
    genToken()
    getEvents()
else:
    getEvents()
exit()