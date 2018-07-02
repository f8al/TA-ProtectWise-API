# this is a required import
import os
import sys
import requests
import logging
import traceback
from logging import handlers
import splunk.admin as admin 
import splunk.auth as auth
from splunk.appserver.mrsparkle.lib.util import make_splunkhome_path

file_name = "protectwise_config"
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

SPLUNK_URL = auth.splunk.getLocalServerInfo()

class ConfigApp(admin.MConfigHandler):
    """
    Set up supported arguments
    """

    def setup(self):
        """
        Set up supported arguments
        """
        try:
            if self.requestedAction == admin.ACTION_EDIT:
                for arg in ['email', 'password', 'api_url']:
                    self.supportedArgs.addOptArg(arg)
        except:
            logger.error("Argument not known in Setup.")
            logger.debug(traceback.format_exc())
            exit(1)

    def _delete_cred(self, realm, username):
        logger.info("function=_delete_cred ")
        r = self._delete("{}/servicesNS/nobody/TA-ProtectWise-API/storage/passwords/{}%3A{}%3A?output_mode=json".format(
            SPLUNK_URL, realm, username))
        return r.status_code, r.json()

    def _update_cred(self, realm, username, password):
        logger.info("function=_update_cred")
        r = self._post("{}/servicesNS/nobody/TA-ProtectWise-API/storage/passwords/{}%3A{}%3A?output_mode=json".format(
            SPLUNK_URL, realm, username), {"password": password})
        return r.status_code, r.json()

    def _create_cred(self, realm, username, password):
        logger.info("function=_create_cred")
        r = self._post("{}/servicesNS/nobody/TA-ProtectWise-API/storage/passwords?output_mode=json".format(
            SPLUNK_URL, realm, username), {'name': username, 'password': password,
                                'realm': realm})
        return r.status_code, r.json()

    def _post(self, url, data):
        try:
            return requests.post(url=url, data=data, headers={'Authorization': 'Splunk ' + self.getSessionKey()},
                          verify=False)
        except Exception, e:
            logger.error("function=_post error={}".format(e))

    def _delete(self, url):
        try:
            return requests.delete(url=url, headers={'Authorization': 'Splunk ' + self.getSessionKey()},
                          verify=False)
        except Exception, e:
            logger.error("function=_delete error={}".format(e))

    def _get(self, url):
        try:
            return requests.get(url=url,
                             headers={'Authorization': 'Splunk ' + self.getSessionKey()},
                             verify=False)

        except Exception, e:
            logger.error("function=_get error={}".format(e))

    def _get_cred(self, realm, username):
        try:
            r = self._get("{}/servicesNS/nobody/TA-ProtectWise-API/storage/passwords/{}%3A{}%3A?output_mode=json".format(
                SPLUNK_URL, realm, username
            ))
            return r.status_code, r.json()
        except Exception, e:
            logger.error("function=_get_cred error={}".format(e))

    def handleList(self, confInfo):
        """
        handleList method: lists configurable parameters in the configuration page
        corresponds to handleractions = list in restmap.conf
        """
        try:
            logger.info("function=handleList status=initial")
            confDict = self.readConf("protectwise")
            logger.debug("protectwise.handleList: " + repr(confDict))
            if confDict is not None:
                for stanza, settings in confDict.items():
                    for key, val in settings.items():
                        confInfo[stanza].append(key, val)
            logger.info("config: {}".format(confDict))
            config = confDict['config']

            if "email" in config:
                logger.info("function=handleList action=get_production_user_credential user={}".format(
                        config["email"]))
                sc, cnt = self._get_cred("protectwise", config["email"])
                if sc == 200:
                    try:
                        confInfo['config']['password'] = cnt['entry'][0]['content']['clear_password']
                    except:
                        confInfo['config']['password'] = cnt['entry'][0]['content']['password']
                else:
                    confInfo['config']['password'] = ''
                confInfo['config']['password_confirm'] = confInfo['config']['password']
        except KeyError, e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            logger.info('no user/key found: line_no={} message={}'.format(exc_tb.tb_lineno, e))
        except Exception, e:
            logger.error("function=handleList error={}".format(e))
        logger.info("function=handleList status=complete")

    def handleEdit(self, confInfo):
        """
        handleEdit method: controls the parameters and saves the values 
        corresponds to handleractions = edit in restmap.conf

        """
        try:
            logger.info("function=handleEdit status=starting")

            email = self.callerArgs.data['email'][0]
            password = self.callerArgs.data['password'][0]
            api_url = self.callerArgs.data['api_url'][0]
            if email is None:
                try:
                    pass
                except Exception, e:
                    exc_type, exc_obj, exc_tb = sys.exc_info()
                    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                    logger.error("action=fatal_error line={} file={}  message={}".format(exc_tb.tb_lineno, fname, e))
            elif len(email) > 0:
                try:
                    logger.info("action=edit realm=protectwise user={}".format(email))
                    sc, cnt = self._get_cred("protectwise", email)
                    if sc == 200:
                        if password is None:
                            # Delete credential
                            sc2, cnt2 = self._delete_cred("protectwise", email)
                            logger.info("action=delete_cred status={}".format(sc2))
                        elif password is not None:
                            # Update in password store via REST interface
                            sc2, cnt2 = self._update_cred("protectwise", email, password)
                            logger.info("action=update_cred status={}".format(sc2))
                        elif len(password) < 1:
                            # Delete credential
                            sc2, cnt2 = self._delete_cred("protectwise", email)
                            logger.info("action=delete_cred status={}".format(sc2))
                    else:
                        # Create in password store via REST interface (Will have no effect if the user exists)
                        # Delete credential
                        sc2, cnt2 = self._create_cred("protectwise", email, password)
                        logger.info("action=create_cred status={}".format(sc2))

                except admin.HandlerSetupException, e:
                    exc_type, exc_obj, exc_tb = sys.exc_info()
                    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                    logger.error("action=arg_validation_fatal_error line={} file={}  message={}".format(exc_tb.tb_lineno, fname, e))
                    raise e
                except Exception, e:
                    exc_type, exc_obj, exc_tb = sys.exc_info()
                    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                    logger.error("action=fatal_error line={} file={}  message={}".format(exc_tb.tb_lineno, fname, e))
                    raise e

            # Fix Nulls
            for key in self.callerArgs.data.keys():
                if self.callerArgs.data[key][0] is None:
                    self.callerArgs.data[key][0] = ''

                # Strip trailing and leading whitespace
                self.callerArgs.data[key][0] = self.callerArgs.data[key][0].strip()
            logger.info("function=handleEdit status=complete")
            self.writeConf('protectwise', 'config', self.callerArgs.data)

        except admin.HandlerSetupException, e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            logger.error(
                "type={} action=arg_validation_fatal_error line={} file={}  message={}".format(type(e), exc_tb.tb_lineno, fname, e))
            raise e
        except Exception, e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            logger.error("action=handleEdit_fatal_error type={} line={} file={}  message={}".format(type(e), exc_tb.tb_lineno, fname, e))
            raise e


# initialize the handler
admin.init(ConfigApp, admin.CONTEXT_NONE)
