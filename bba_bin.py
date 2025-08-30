#!/usr/bin/env python

import atexit
import serial
import socket
import os
import logging
import logging.handlers
import sys
import time
import subprocess
import sh
import signal
import re
import config_server
import urllib
import urllib2
import iptc
import commands
import urllib2 as urlreq

from dcnow import DreamcastNowService
from datetime import datetime, timedelta

# BBA Mode tool written by scrivanidc@gmail.com - jun/2023
# ------------------------------------------------------------------------------------------------------
# This is a modificated version of original Kazades dreampi.py structure
# All non usable elements where deleted
# DNS query function game based implemented
# BBA movements reading implemented
# DNS Injection "query[A]" + [TCPDUMP Reading URL] to ensure DCNOW Update
# Multiplayer or Browsing(BBA Portal) over DC+LAN are able to be detected on DCNOW
# Dreamcast Ethernet Devices:
# Broadbad Adapter HIT-0400 Realtek RTL8139C 10/100 Mbps 100Base-T
# LAN Adapter HIT-0300 Fujitsu MB86967 10/10 Mbps 10Base-T
# ------------------------------------------------------------------------------------------------------


logger = logging.getLogger('dreampi BBA Mode')

def check_internet_connection():
    """ Returns True if there's a connection """

    IP_ADDRESS_LIST = [
        "1.1.1.1",  # Cloudflare
        "1.0.0.1",
        "8.8.8.8",  # Google DNS
        "8.8.4.4",
        "208.67.222.222",  # Open DNS
        "208.67.220.220"
    ]

    port = 53
    timeout = 3

    for host in IP_ADDRESS_LIST:
        try:
            socket.setdefaulttimeout(timeout)
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))
            return True
        except socket.error:
            pass
    else:
        logger.exception("No internet connection")
        return False

class Daemon(object):
    def __init__(self, pidfile, process):
        self.pidfile = pidfile
        self.process = process

    def daemonize(self):
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)

        except OSError:
            sys.exit(1)

        os.chdir("/")
        os.setsid()
        os.umask(0)

        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError:
            sys.exit(1)

        atexit.register(self.delete_pid)
        pid = str(os.getpid())
        with open(self.pidfile, 'w+') as f:
            f.write("%s\n" % pid)

    def delete_pid(self):
        os.remove(self.pidfile)

    def _read_pid_from_pidfile(self):
        try:
            with open(self.pidfile, 'r') as pf:
                pid = int(pf.read().strip())
        except IOError:
            pid = None
        return pid

    def start(self):
        pid = self._read_pid_from_pidfile()

        if pid:
            logger.info("Daemon already running, exiting")
            sys.exit(1)

        logger.info("Starting daemon")
        self.daemonize()
        self.run()

    def stop(self):
        pid = self._read_pid_from_pidfile()

        if not pid:
            logger.info("pidfile doesn't exist, deamon must not be running")
            return

        try:
            while True:
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.1)

        except OSError:
            if os.path.exists(self.pidfile):
                os.remove(self.pidfile)
            else:
                sys.exit(1)

    def restart(self):
        self.stop()
        self.start()

    def run(self):
        self.process()

class GracefulKiller(object):
    def __init__(self):
        self.kill_now = False
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

    def exit_gracefully(self, signum, frame):
        logging.warning("Received signal: %s", signum)
        self.kill_now = True

def dns():

    port = 80
    timeout = 3

    print("")
    print("Trying DNS Lookup")
    var=int(sys.argv[1])
    if var == 1:
		hosts = ["game01.st-pso.games.sega.net"]
    elif var == 2:
		hosts = ["master.quake3arena.com"]
    elif var == 3:
		hosts = ["master.4x4evolution.com"]
    elif var == 4:
		hosts = ["auriga.segasoft.com"]
    elif var == 5:
		hosts = ["chuchu.games.dream-key.com"]
    elif var == 6:
                hosts = ["daytona.web.dreamcast.com"]
    elif var == 7:
                hosts = ["ddplanet.sega.co.jp"]
    elif var == 8:
                hosts = ["strikers.realityjump.co.uk"]
    elif var == 9:
		hosts = ["authorize.vc-igp.games.sega.net"]
    elif var == 10:
		hosts = ["coolpool.east.won.net"]
    elif var == 11:
		hosts = ["ca1203.mmcp6"]
    elif var == 12:
		hosts = ["connect.gameloft.com"]
    elif var == 13:
		hosts = ["peerchat.gamespy.com"]
    elif var == 14:
		hosts = ["authorize.vc-ooga.games.sega.net"]
    elif var == 15:
		hosts = ["gamestats.pba2001.com"]
    elif var == 16:
		hosts = ["connect.gameloft.com"]
    elif var == 17:
		hosts = ["master.ring.dream-key.com"]
    elif var == 18:
		hosts = ["master.gamespy.com"]
		port = 6500
    elif var == 19:
		hosts = ["gamesauth.dream-key.com"]
    elif var == 20:
		hosts = ["master.worms.dream-key.com"]
    elif var == 21:
                hosts = ["AUTHORIZE.VC-NBA2K1.GAMES.SEGA.NET"]
    elif var == 22:
                hosts = ["AUTHORIZE.VC-NBA2K2.GAMES.SEGA.NET"]
    elif var == 23:
                hosts = ["AUTHORIZE.VC-NCAA2K2.GAMES.SEGA.NET"]
    elif var == 24:
                hosts = ["AUTHORIZE.VC-NFL2K1.GAMES.SEGA.COM"]
    elif var == 25:
                hosts = ["AUTHORIZE.VC-NFL2K2.GAMES.SEGA.NET"]
    else:
		hosts = ["google.com"]

    for host in hosts:
        try:
            nowip = commands.getoutput("hostname -I | awk '{print $1}'")
            socket.setdefaulttimeout(timeout)
            dcnow = DreamcastNowService()
            dcnow.go_online(nowip)
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect((host, port))

            print ""
            print "Host reached - " + host + ":" + str(port)
            print ""
            print "Check Dreamcast Now page"

            return True
        except socket.error:
			pass
    else:
        print ""
        print "Host not reached - " + host + ":" + str(port)
        print ""
        print "Check Dreamcast Now page"
        print ""

        return True


def main():
    try:
        # Don't do anything until there is an internet connection
        while not check_internet_connection():
            logger.info("Waiting for internet connection...")
            time.sleep(3)

        config_server.start()

        logger.info("Starting Dreamcast Now")

        var=int(sys.argv[1])

        if var == 0:
            dev=sys.argv[2]
            # If BBA Mode > TCP Dump on ethernet port to read Dreamcast moves
            subprocess.check_output("tcpdump -i " + dev + " -vv >> /tmp/capture1 &", shell=True)
            nowip = commands.getoutput("hostname -I | awk '{print $1}'")
            dcnow = DreamcastNowService()
            dcnow.go_online(nowip)

        else:
            subprocess.check_output("echo 1 > /tmp/capture1", shell=True)
            dns()

        loop = True
        while(loop):
            time.sleep(5)

            # Toy Racer packet monitoring
            subprocess.check_output("grep -a '.2048 ' /tmp/capture1 | cut -d ':' -f 1 | grep '.2048 ' | awk '{print $3;}' >> /tmp/capture2", shell=True)
            # If there is communication under 2048 toy racer port, we inject the correct DNS Query, cause there is no URL at all on BBA Toy Racer communications
            subprocess.check_output("sed -i -e 's/^/gamesauth.dream-key.com /' /tmp/capture2", shell=True)

            # Other BBA Games packet monitoring for DNS query research, to  ensure we send the game flag to Now
            subprocess.check_output("grep -a 'A? ' /tmp/capture1 | cut -d ':' -f 3 | grep 'A? ' | awk '{print $2;}' | sed 's/\.$//' >> /tmp/capture2", shell=True)
            # If we have a Toy Racer detection, this sed commando will add query[A] to initial of line, before the gamesauth.dream-key, if is other BBA Game, the grep above this that will actually populate capture2 file and we don't have the first toy racer sed injection.
            subprocess.check_output("sed -i -e 's/^/dnsmasq[0000]: query[A] /' /tmp/capture2", shell=True)

            # Remove any duplicate value
            subprocess.check_output("sort /tmp/capture2 | uniq | tee /tmp/capture2", shell=True)

            f = open("/tmp/capture2")
            lines = f.readlines()
            for line in lines:
                logger.info(line)

            subprocess.check_output("truncate -s 0 /tmp/capture*", shell=True)

            time.sleep(5)
    except:
        logger.exception("Something went wrong...")
    finally:

        config_server.stop()
        logger.info("Dreampi BBA Mode quit successfully")
        exit()

if __name__ == '__main__':
    logger.setLevel(logging.INFO)
    handler = logging.handlers.SysLogHandler(address='/dev/log')
    logger.addHandler(handler)

    if len(sys.argv) > 1 and "--no-daemon" in sys.argv:
        logger.addHandler(logging.StreamHandler())
        sys.exit(main())

    daemon = Daemon("/tmp/dreampi.pid", main)

    if len(sys.argv) == 2:
        if sys.argv[1] == "start":
            daemon.start()
        elif sys.argv[1] == "stop":
            daemon.stop()
        elif sys.argv[1] == "restart":
            daemon.restart()
        else:
            sys.exit(2)
        sys.exit(0)
    else:
        print("Usage: %s start|stop|restart" % sys.argv[0])
        sys.exit(2)
