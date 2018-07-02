import requests
import json
import time
import splunk.clilib.cli_common as scc
import os
import logging
import sys
from logging import handlers
import splunk.auth as auth
from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path

file_name = "protectwise_script"
log_location = make_splunkhome_path(['var', 'log', 'splunk', "TA-ProtectWise-API"])
_log = logging.getLogger("{}".format(file_name))
if not os.path.isdir(log_location):
    os.mkdir(log_location)
output_file_name = os.path.join(log_location, "{}.log".format(file_name))
_log.propogate = False
_log.setLevel(logging.DEBUG)
f_handle = handlers.RotatingFileHandler(output_file_name, maxBytes=25000000, backupCount=5)
formatter = logging.Formatter(
    '%(asctime)s log_level=%(levelname)s pid=%(process)d tid=%(threadName)s file="%(filename)s" function="%(funcName)s" line_number="%(lineno)d"  %(message)s'.format(
    ))
f_handle.setFormatter(formatter)
if not len(_log.handlers):
    _log.addHandler(f_handle)
logger = _log
logger.info("setup initial script")
SPLUNK_URL = auth.splunk.getLocalServerInfo()

session_key = ""
try:
    session_key = sys.stdin.readline().strip()
except Exception as e:
    logger.error("{}".format(e))

def _get(url):
    try:
        return requests.get(url=url,
                            headers={'Authorization': 'Splunk ' + session_key},
                            verify=False)

    except Exception, e:
        logger.error("function=_get error={}".format(e))


def _get_cred(realm, username):
    try:
        r = _get("{}/servicesNS/nobody/TA-ProtectWise-API/storage/passwords/{}%3A{}%3A?output_mode=json".format(
            SPLUNK_URL, realm, username
        ))
        if r.status_code == 200:
            j = r.json()
            return j["entry"][0]["content"]["clear_password"]
        else:
            raise Exception("Failed to get creds.")
    except Exception, e:
        logger.error("function=_get_cred error={}".format(e))


#load configuration file
config = scc.getConfStanza("protectwise", "config")
logger.info("pulled config {}".format(config))
apiUrl = config.get('api_url', None)
header = {'Content-Type': 'application/json'}
payload = {"email": config.get('email', None), "password": _get_cred('protectwise', config.get('email', None))}
logger.debug("payload {}".format(payload))
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
if tr.status_code == requests.codes.unauthorized:
    genToken()
    getEvents()
else:
    getEvents()
exit(0)