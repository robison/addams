"""
morticia.py
Tool to dump complete config of Gomez Performance Network account
This is based on some work done by Nordstrom at
https://github.com/Nordstrom/compuware_apm_gpn
"""

#!/usr/bin/python
# -*- coding: utf-8 -*-

import binascii
import json
import os
import sys
import xml.sax.saxutils
import xml.dom.minidom

from optparse import OptionParser

try:
    import xmltodict
    from suds.client import Client
    from suds.sudsobject import asdict
except ImportError:
    egg_dir = './'
    for filename in os.listdir(egg_dir):
        if filename.endswith(".egg"):
            sys.path.append(egg_dir + filename)
    import xmltodict
    from suds.client import Client
    from suds.sudsobject import asdict


def xmlparse(data):
    """ Converts XML string object to a Python dict """
    return xmltodict.parse(data,
                           process_namespaces=False,
                           attr_prefix='',
                           item_depth=0)


def recursive_asdict(data):
    """ Convert Suds object into serializable format. """
    out = {}
    for key, value in asdict(data).iteritems():
        if hasattr(value, '__keylist__'):
            out[key] = recursive_asdict(value)
        elif isinstance(value, list):
            out[key] = []
            for item in value:
                if hasattr(item, '__keylist__'):
                    out[key].append(recursive_asdict(item))
                else:
                    out[key].append(item)
        else:
            out[key] = value
    return out


def recursive_decode(data):
    """
    Recursively convert base64-encoded key/value pairs to string, then attempt
    to json.loads the result to test for additional base64-encoded JSON values
    """

    if isinstance(data, (int, float, long, complex)):
        out = str(data)
    elif isinstance(data, dict):
        out = {}
        for key, value in data.iteritems():
            key = key.decode('utf-8')
            out[key] = recursive_decode(value)
    elif isinstance(data, list):
        out = []
        for i in data:
            try:
                out.append(recursive_decode(i))
            except UnicodeEncodeError:
                out.append(i.decode('utf-8'))
    elif isinstance(data, (str, unicode)):
        try:
            out = data.decode('base64', 'strict').encode('utf-8')
        except (TypeError, ValueError, binascii.Error):
            out = data.decode('utf-8')
        else:
            try:
                json_data = json.loads(out)
                out = json_decode(json_data)
            except (ValueError, AttributeError):
                pass
    else:
        out = data
    return out


def json_decode(data):
    """
    Attempts to json.loads() data; if successful, returns either a dict or a
    list with the values found.
    """
    try:
        out = {}
        for key, value in data.iteritems():
            out[key.decode('utf-8')] = recursive_decode(value)
    except AttributeError:
        out = []
        for i in data:
            out.append(recursive_decode(i))
    return out


class Gpn(Client):
    """
    Class to handle the interaction with the Gomez SOAP API via the
    suds.client.Client module
    """
    def __init__(self,
                 username,
                 password,
                 url=None):
        """
        @param username: The username for the service.
        @type username: str
        @param password: The password for the service.
        @type password: str
        @param url: The WSDL url for the service.
        @type url: str
        """
        self.username = username
        self.password = password
        self.url = url
        self.soapclient = Client(self.url, retxml=False)

    def __str__(self):
        return '[user: %s\tpassword: %s\twsdl: %s]' % (self.username,
                                                       self.password,
                                                       self.url)

    def service(self, transport=None):
        """
        The B{service} selector is used to select a web service.
        In most cases, the wsdl only defines (1) service in which access
        by subscript is passed through to a L{PortSelector}.  This is also the
        behavior when a I{default} service has been specified.  In cases
        where multiple services have been defined and no default has been
        specified, the service is found by name (or index) and an
        L{PortSelector} for the service is returned.  In all cases, attribute
        access is forwarded to the L{PortSelector} for either the I{first}
        service or the I{default} service (when specified).
        @ivar __client: A suds client.
        @type __client: L{Client}
        @ivar __services: A list of I{wsdl} services.
        @type __services: list
        """
        if transport:
            self.soapclient = Client(self.url, transport=None, retxml=True)
        return self.soapclient.service

    def last_sent(self):
        """
        Get last sent I{soap} message.
        @return: The last sent I{soap} message.
        @rtype: L{Document}
        """
        return self.soapclient.last_sent()

    def last_received(self):
        """
        Get last received I{soap} message.
        @return: The last received I{soap} message.
        @rtype: L{Document}
        """
        return self.soapclient.last_received()


class Account(Gpn):
    """ Class to handle & gather account information """
    def __init__(
            self,
            username,
            password,
            url='https://gsr.webservice.gomez.com/' +
            'gpnaccountmanagementservice/GpnAccountManagementService.asmx?WSDL'
    ):
        """
        @param username: The username for the service.
        @type username: str
        @param password: The password for the service.
        @type password: str
        @param url: The WSDL url for the service.
        @type url: str
        """
        Gpn.__init__(self, username, password, url)

    def get_account_info(self):
        """ Get summary for the account """
        return self.service().GetAccountSummary(
            sUsername=self.username,
            sPassword=self.password)

    def get_account_sites(self):
        """ Get list of test sites available to your account """
        return self.service().GetAccountSites(
            sUsername=self.username,
            sPassword=self.password)

    def get_account_backbones(self):
        """ Get backbone provider listing available to your account """
        return self.service().GetAccountBackbones(
            sUsername=self.username,
            sPassword=self.password)

    def get_account_config(self):
        """
        Get the entirety of the account config package;
        is actually incomplete.
        """
        return self.service().GetAccountConfigPackage(
            sUsername=self.username,
            sPassword=self.password)

    def get_account_monitors(self,
                             monitorsetdesignator='ALL',
                             statusdesignator='ALL'):
        """
        Get a list of the account monitors; set statusdesignator to ALL to
        retrieve a list of all account monitors instead of just active ones
        """
        return self.service().GetAccountMonitors(
            sUsername=self.username,
            sPassword=self.password,
            sMonitorSetDesignator=monitorsetdesignator,
            sStatusDesignator=statusdesignator)

    def get_monitor_sites(self, monitorid=None):
        """ Get a list of the sites configured for each monitor """
        return self.service().GetMonitorSites(
            sUsername=self.username,
            sPassword=self.password,
            iMonitorId=monitorid)


class Script(Gpn):
    """ Class to handle & gather script information """
    def __init__(self,
                 username,
                 password,
                 url='https://gsr.webservice.gomez.com/' +
                 'utascriptservice/UtaScriptService.asmx?WSDL'):
        """
        @param username: The username for the service.
        @type username: str
        @param password: The password for the service.
        @type password: str
        @param url: The WSDL url for the service.
        @type url: str
        """
        Gpn.__init__(self, username, password, url)

    def delete_script(self, monitorid=None):
        """ Deletes script """
        return self.service().DeleteScript(sUsername=self.username,
                                           sPassword=self.password,
                                           iMonitorId=monitorid)

    def get_script(self, monitorid=None, siteid='0'):
        """ Gets script info for a given monitor & site """

        return self.service().GetScript(sUsername=self.username,
                                        sPassword=self.password,
                                        iMonitorId=monitorid,
                                        iSiteId=siteid)

    def load_script(self, desc=None, xmlbuffer=None):
        """ Loads a new script; returns a script ID """
        return self.service().LoadScript(sUsername=self.username,
                                         sPassword=self.password,
                                         sDescription=desc,
                                         cXmlBuffer=xmlbuffer)

    def replace_script(self, desc=None, monitorid=None, xmlbuffer=None):
        """ Replaces an existing script ID with new script info """
        return self.service().ReplaceScript(sUsername=self.username,
                                            sPassword=self.password,
                                            sDescription=desc,
                                            iMonitorId=monitorid,
                                            cXmlBuffer=xmlbuffer)


class Alert(Gpn):
    """ Class to handle & gather Alert information """
    def __init__(self, username, password,
                 url='https://gsr.webservice.gomez.com/' +
                 'AlertManagementService/AlertManagementWS.asmx?WSDL'):
        """
        @param username: The username for the service.
        @type username: str
        @param password: The password for the service.
        @type password: str
        @param url: The WSDL url for the service.
        @type url: str
        """
        Gpn.__init__(self, username, password, url)

    def get_alert_history(self,
                          monitortype='ALL',
                          starttime=None,
                          endtime=None):
        """ Get alert history from Gomez API """
        return self.service().GetAlertHistory(username=self.username,
                                              password=self.password,
                                              monitorType=monitortype,
                                              startTime=starttime,
                                              endTime=endtime)

    def get_alert_states(self, monitortype='ALL'):
        """ Get current alert states from Gomez API """
        return self.service().GetAlertStates(username=self.username,
                                             password=self.password,
                                             monitorType=monitortype)

    def get_alert_configuration(self,
                                monitortype='ALL',
                                statustype='ALL'):
        """ Get alerts config from Gomez API """
        return self.service().GetCompleteAlertConfiguration(
            username=self.username,
            password=self.password,
            monitorType=monitortype,
            statusType=statustype)


def get_monitor_info(login):
    """ Get all monitor (read: tests) info from Gomez AccountMgmt API """
    monitor_info = {}
    monitordata = login.get_account_monitors()
    monitors = recursive_asdict(monitordata)
    for i in monitors['MonitorSet']['Monitor']:
        monitor_info[i['_mid']] = i
    monitor_info.pop("Status", None)
    return monitor_info


def get_alert_info(login):
    """ Get alert info from Gomez AlertManagementService API """
    alert_info = {}
    alertdata = login.get_alert_configuration()
    alerts = recursive_asdict(alertdata)
    for i in alerts['monitorAlertConfiguration']:
        alert_info[str(i['_id'])] = i
    alert_info.pop("Status", None)
    return alert_info


def get_site_info(login, mid, sites):
    """ Get info about all sites used by a monitor """
    site_info = {}
    sites[mid] = recursive_asdict(login.get_monitor_sites(mid))
    try:
        for i in sites[mid]['SiteSet']['Site']:
            site = {}
            for key, value in i.iteritems():
                site[key.encode('utf-8')] = value.encode('utf-8')
            site_info[i['_sid'].encode('utf-8')] = site
    except KeyError:
        pass
    else:
        return site_info


def get_script_info(login, mid, sid):
    """ Get script info for a monitor/site pair """
    scripts = {}
    scripts[mid] = login.get_script(mid, sid)
    try:
        script_info = xmlparse(scripts[mid]['ScriptXml'])
    except TypeError:
        pass
    else:
        return script_info


def build_config(username, password):
    """ Builds account config from Gomez APIs """
    dataset = {}
    monitors = get_monitor_info(Account(username, password))
    alertinfo = get_alert_info(Alert(username, password))
    for mid in monitors:
        monitors[mid].pop("Status", None)
        sites = {}
        siteinfo = {}
        scriptinfo = {}
        if mid not in alertinfo:
            alertinfo[mid] = {}
        siteinfo[mid] = get_site_info(Account(username, password), mid, sites)
        for i in sites:
            scriptinfo[mid] = get_script_info(Script(username, password),
                                              mid, i)
        dataset[mid] = {u'alerts': alertinfo[mid],
                        u'monitor': monitors[mid],
                        u'script': scriptinfo[mid],
                        u'sites': siteinfo[mid]}
    return dataset


def main():
    """ Main program - command line options, etc """
    usage = ("usage: %prog [-h|--help] [-u|--username <username>] " +
             "[-p|--password <password>]")
    parser = OptionParser(usage=usage, version="%prog 0.1")
    parser.add_option("-u",
                      "--username",
                      type="string",
                      dest="username",
                      help="Username")
    parser.add_option("-p",
                      "--password",
                      type="string",
                      dest="password",
                      help="Password")
    (options, args) = parser.parse_args()

    config = build_config(options.username, options.password)
    config = recursive_decode(config)
    print json.dumps(config,
                     encoding='utf-8',
                     ensure_ascii=False,
                     indent=4,
                     separators=(',', ': '),
                     sort_keys=True).encode('utf-8')


if __name__ == '__main__':
    main()
