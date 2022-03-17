#!/usr/bin/env python3

from __future__ import absolute_import

import json
import threading
import cgi
import os
from typing import Dict, List
from http.server import BaseHTTPRequestHandler, HTTPServer

from dcnow import CONFIGURATION_FILE, hash_mac_address


class DreamPiConfigurationService(BaseHTTPRequestHandler):

    def _get_post_data(self) -> Dict[str, List[str]]:
        ctype, pdict = cgi.parse_header(self.headers['content-type'])

        if ctype == 'multipart/form-data':
            pdict = { k: v.encode() for k, v in pdict.items() }
            postvars = cgi.parse_multipart(self.rfile, pdict)
        elif ctype == 'application/x-www-form-urlencoded':
            length = int(self.headers['content-length'])
            postvars = cgi.parse_qs(self.rfile.read(length).decode(), keep_blank_values=True)
        else:
            postvars = {}

        return postvars

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        enabled_state = True
        if os.path.exists(CONFIGURATION_FILE):
            with open(CONFIGURATION_FILE, "r") as f:
                enabled_state = json.loads(f.read())["enabled"]

        self.wfile.write(json.dumps({
            "mac_address": hash_mac_address(),
            "is_enabled": enabled_state
        }).encode())


    def do_POST(self):
        enabled_state = True

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        post_data = self._get_post_data()
        if 'disable' in post_data:
            enabled_state = False
        else:
            enabled_state = True

        with open(CONFIGURATION_FILE, "w") as f:
            f.write(json.dumps({"enabled": enabled_state}))

        self.wfile.write(json.dumps({
            "mac_address": hash_mac_address(),
            "is_enabled": enabled_state
        }).encode())


server = None
thread = None

def start():
    global server
    global thread
    server = HTTPServer(('0.0.0.0', 1998), DreamPiConfigurationService)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()

def stop():
    global server
    global thread

    if server:
        server.shutdown()

    if thread:
        thread.join()
