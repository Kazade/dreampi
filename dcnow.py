#!/usr/bin/env python
#dcnow.py_version=202609091030
import threading
import os
import json
import time
import logging
import socket
import ssl
import urllib
import urllib2
import sh

from hashlib import sha256

from uuid import getnode as get_mac

logger = logging.getLogger('dcnow')

API_ROOT = "https://dcnow-2016.appspot.com"
UPDATE_END_POINT = "/api/update/{mac_address}/"

UPDATE_INTERVAL = 15

CONFIGURATION_FILE = os.path.expanduser("~/.dreampi.json")

# Hostnames shared by several games. DCNow maps a domain to a single game,
# so re-sending one of these every UPDATE_INTERVAL would keep overwriting
# the entry (including a manual correction). Report each one once per
# session; later polls post an empty update to keep the session alive.
SHARED_DOMAINS = (
    "gameloft",
    "onsen0.overworks.isao.net",
)
sent_shared = set()

def scan_mac_address():
    mac = get_mac()
    return sha256(':'.join(("%012X" % mac)[i:i+2] for i in range(0, 12, 2))).hexdigest()

class DreamcastNowThread(threading.Thread):
    def __init__(self, service):
        self._service = service
        self._running = True
        super(DreamcastNowThread, self).__init__()

    def run(self):
        def post_update():
            if not self._service._enabled:
                return
            lines = [ x for x in sh.tail("/var/log/syslog", "-n", "15", _iter=True) ]
            dns_query = None
            for line in lines[::-1]:
                if "query[A]" in line:
                    # We did a DNS lookup, what was it?
                    remainder = line[line.find("query[A]") + len("query[A]"):].strip()
                    domain = remainder.split(" ", 1)[0].strip()
                    dns_query = sha256(domain).hexdigest()
                    
                    #Send shared-host games (monaco/pod/speed, onsen0) just once - Begin
                    shared = next((d for d in SHARED_DOMAINS if d in domain), None)
                    if shared is not None:
                        if shared in sent_shared: ## already sent, do not send again.
                            dns_query = None
                            break
                        sent_shared.add(shared) ## first read, send.
                        logger.info("Domain sent to DCNow API: " + domain)
                        break
                    #Send shared-host games just once - End

                    if "appspot" in domain:
                        pass
                    else:
                        logger.info("Domain sent to DCNow API: " + domain)
                        break

            user_agent = 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT), Dreamcast Now'
            header = { 'User-Agent' : user_agent }
            mac_address = self._service._mac_address
            data = {}
            if dns_query:
                data["dns_query"] = dns_query

            data = urllib.urlencode(data)
            req = urllib2.Request(API_ROOT + UPDATE_END_POINT.format(mac_address=mac_address), data, header)
            # Explicit timeout: dreampi's check_internet_connection() calls
            # socket.setdefaulttimeout(3) and never restores it, which is too
            # tight for a TLS round trip to App Engine from a Pi.
            urllib2.urlopen(req, timeout=15) # Send POST update

        while self._running:
            try:
                post_update()
            except (urllib2.URLError, ssl.SSLError, socket.error) as e:
                # Transient network trouble is expected and self-correcting;
                # the POST usually arrived and only the reply was lost. One
                # line rather than a 20-line traceback every UPDATE_INTERVAL.
                logger.info("Dreamcast Now update failed: %s" % e)
            except:
                logger.exception("Couldn't update Dreamcast Now!")
            dcnow_run.wait(UPDATE_INTERVAL)

    def stop(self):
        self._running = False
        self.join()


class DreamcastNowService(object):
    def __init__(self):
        self._thread = None
        self._mac_address = None
        self._enabled = True
        self.reload_settings()

        logger.setLevel(logging.INFO)
        # 'dcnow' is a module-level logger, so every DreamcastNowService()
        # would add another handler to the same object and each message
        # would be logged once per instance ever created.
        if not logger.handlers:
            handler = logging.handlers.SysLogHandler(address='/dev/log')
            formatter = logging.Formatter('%(name)s[%(process)d]: %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)

    def update_mac_address(self, dreamcast_ip):
        self._mac_address = scan_mac_address()
        logger.info("MAC address: {}".format(self._mac_address))

    def reload_settings(self):
        settings_file = CONFIGURATION_FILE

        if os.path.exists(settings_file):
            with open(settings_file, "r") as settings:
                content = json.loads(settings.read())
                self._enabled = content["enabled"]

    def go_online(self, dreamcast_ip):
        logger.propagate = False
        if not self._enabled:
            return
        global dcnow_run
        dcnow_run = threading.Event()
        self.update_mac_address(dreamcast_ip)
        self._thread = DreamcastNowThread(self)
        self._thread.start()
        logger.info("DC Now Session Started")

    def go_offline(self):
        global dcnow_run
        sent_shared.clear()
        if self._thread is None:
            return  # go_online() never started a session (service disabled)
        dcnow_run.set()
        self._thread.stop()
        self._thread = None
        logger.info("DC Now Session Ended")
