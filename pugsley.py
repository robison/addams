"""
pugsley.py
Tool to dump complete config of Gomez Performance Network account
This is based on some work done by Nordstrom at
https://github.com/Nordstrom/compuware_apm_gpn
"""

#!/usr/bin/python
# -*- coding: utf-8 -*-

from morticia import Account, Alert, Decode, Script
from optparse import OptionParser


class Gather(object):
    """
    Gather info from Gomez API via SOAP interface
    """
    @classmethod
    def get_monitor_info(cls, login):
        """ Get all monitor (read: tests) info from Gomez AccountMgmt API """
        monitor_info = {}
        monitordata = login.get_account_monitors()
        monitors = Decode.recursive_asdict(monitordata)
        for i in monitors['MonitorSet']['Monitor']:
            monitor_info[i['_mid']] = i
        monitor_info.pop("Status", None)
        return monitor_info

    @classmethod
    def get_alert_info(cls, login):
        """ Get alert info from Gomez AlertManagementService API """
        alert_info = {}
        alerts = Decode.recursive_asdict(login.get_alert_configuration())
        for i in alerts['monitorAlertConfiguration']:
            alert_info[str(i['_id'])] = i
        alert_info.pop("Status", None)
        return alert_info

    @classmethod
    def get_site_info(cls, login, mid):
        """ Get info about all sites used by a monitor """
        site_info = {}
        sites = Decode.recursive_asdict(login.get_monitor_sites(mid))
        try:
            for i in sites['SiteSet']['Site']:
                site = {}
                for key, value in i.iteritems():
                    site[key.encode('utf-8')] = value.encode('utf-8')
                site_info[i['_sid'].encode('utf-8')] = site
        except KeyError:
            pass
        sites.pop("Status", None)
        return site_info

    @classmethod
    def get_script_info(cls, login, mid, sid):
        """ Get script info for a monitor/site pair """
        scripts = {}
        scripts[mid] = login.get_script(mid, sid)
        try:
            script_info = Decode.xmlparse(scripts[mid]['ScriptXml'])
        except TypeError:
            pass
        else:
            return script_info


class Build(object):
    """
    Build config for output
    """
    @classmethod
    def config(cls, username, password):
        """ Builds account config from Gomez APIs """
        dataset = {}
        alertinfo = Gather.get_alert_info(Alert(username, password))
        monitors = Gather.get_monitor_info(Account(username, password))
        scriptinfo = {}
        for mid in monitors:
            monitors[mid].pop("Status", None)
            siteinfo = {}
            scriptinfo = {}
            scriptinfo[mid] = {}
            if mid not in alertinfo:
                alertinfo[mid] = {}
            siteinfo[mid] = Gather.get_site_info(Account(username,
                                                         password),
                                                 mid)
            for i in siteinfo[mid]:
                scriptinfo[mid] = Gather.get_script_info(Script(username,
                                                                password),
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

    config = Build.config(options.username, options.password)
    config = Decode.recursive_decode(config)
    print Decode.json_dumps(config)


if __name__ == '__main__':
    main()
