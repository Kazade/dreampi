#!/usr/bin/env python

import threading
import os
import json
import subprocess
import time
import logging
import urllib
import urllib2

logger = logging.getLogger('dcnow')

API_ROOT = "https://dcnow-2016.appspot.com"
END_POINT = "/update"

UPDATE_INTERVAL = 30


class DreamcastNowThread(threading.Thread):
    def __init__(self, service):
        self._service = service
        self._running = True
        super(DreamcastNowThread, self).__init__()

    def run(self):
        def post_update():
            user_agent = 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT), Dreamcast Now'
            header = { 'User-Agent' : user_agent }
            data = {
                "username": self._service.username,
                "mac": self._service._mac_address
            }

            data = urllib.urlencode(data)
            req = urllib2.Request(API_ROOT + END_POINT, data, header)
            urllib2.urlopen(req) # Send POST update

        while self._running:
            post_update()
            time.sleep(UPDATE_INTERVAL)

    def stop(self):
        self._running = False
        self.join()


class DreamcastNowService(object):
    def __init__(self):
        self._thread = None
        self._mac_address = None
        self._username = None
        self._enabled = True
        self.reload_settings()

        logger.setLevel(logging.INFO)
        handler = logging.handlers.SysLogHandler(address='/dev/log')
        logger.addHandler(handler)

    @property
    def username(self):
        if self._username:
            return self._username

        if self._mac_address:
            return "Unnamed_{}".format(self._mac_address.replace(":", ""))

        raise Exception("Either mac address or username must be set before accessing username")


    def update_mac_address(self, dreamcast_ip):
        def scan_mac_address(ip):
            output = subprocess.check_output(["sudo", "nmap", "-Pn", dreamcast_ip])

            for line in output.split("\n"):
                if line.startswith("MAC"):
                    return line.split(":", 1)[1].strip().split(" ", 1)[0]
            else:
                return None

        self._mac_address = scan_mac_address(dreamcast_ip)
        logger.info("MAC address: {}".format(self._mac_address))

    def reload_settings(self):
        settings_file = os.path.expanduser("~/.dcnow.json")

        if os.path.exists(settings_file):
            with open(settings_file, "r") as settings:
                content = json.loads(settings.read())
                self._username = content["username"]
                self._enabled = content["enabled"]


    def go_online(self, dreamcast_ip):
        if not self._enabled:
            return

        self.update_mac_address(dreamcast_ip)
        self._thread = DreamcastNowThread(self)
        self._thread.start()

    def go_offline(self):
        self._thread.stop()
        self._thread = None
