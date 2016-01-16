import json
import threading
import cgi

from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer


ENABLED_STATE = True


class DreamPiConfigurationService(BaseHTTPRequestHandler):

    def _get_post_data(self):
        ctype, pdict = cgi.parse_header(self.headers.getheader('content-type'))
        if ctype == 'multipart/form-data':
            postvars = cgi.parse_multipart(self.rfile, pdict)
        elif ctype == 'application/x-www-form-urlencoded':
            length = int(self.headers.getheader('content-length'))
            postvars = cgi.parse_qs(self.rfile.read(length), keep_blank_values=1)
        else:
            postvars = {}

        return postvars

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        self.wfile.write(json.dumps({
            "mac_address": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "is_enabled": ENABLED_STATE
        }))


    def do_POST(self):
        global ENABLED_STATE

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        post_data = self._get_post_data()
        if 'disable' in post_data:
            ENABLED_STATE = False
        else:
            ENABLED_STATE = True

        self.wfile.write(json.dumps({
            "mac_address": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "is_enabled": ENABLED_STATE
        }))


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
    server.shutdown()
    thread.join()
