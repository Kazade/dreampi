#!/usr/bin/env python

import serial
import os
import logging
import sys
import time
from datetime import datetime, timedelta


MODEM_DEVICE = "ttyACM0"


class Daemon(object):
    def __init__(self, pidfile, process):
        self.pidfile = pidfile
        self.process = process

    def deamonize(self):
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)

        except OSError, e:
            sys.exit(1)

        os.chdir("/")
        os.setsid()
        os.umask(0)

        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError, e:
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

    def start(self):
        pid = self._read_pid_from_pidfile()

        if pid:
            logging.info("Daemon already running, exiting")
            sys.exit(1)

        logging.info("Starting daemon")
        self.daemonize()
        self.run()

    def stop(self):
        pid = self._read_pid_from_pidfile()

        if not pid:
            logging.info("pidfile doesn't exist, deamon must not be running")
            return

        try:
            while True:
                os.kill(pid, SIGTERM)
                time.sleep(0.1)

        except OSError as err:
            if os.path.exists(self.pidfile):
                os.remove(self.pidfile)
            else:
                sys.exit(1)

    def restart(self):
        self.stop()
        self.start()

    def run(self):
        self.process()



def connect_to_modem():
    logging.info("Connecting to modem...")
    dev = serial.Serial("/dev/" + MODEM_DEVICE, timeout=0)

    logging.info("Connected.")
    return dev


def send_command(modem, command):
    final_command = "%s\r\n" % command
    modem.write(final_command)
    logging.info(final_command)


def main():
    modem = connect_to_modem()

    # Send the initialization string to the modem
    send_command(modem, "ATZE1") # RESET
    send_command(modem, "AT+FCLASS=8")  # Switch to Voice mode
    send_command(modem, "AT+VLS=1") # Go online

    logging.info("Setup complete, listening...")

    time_since_last_digit = None
    time_since_last_dial_tone = datetime.now() - timedelta(seconds=3)

    while True:
        now = datetime.now()
        delta_seconds = (now - time_since_last_dial_tone).total_seconds()
        if delta_seconds >= 2.55:
            #modem.write("AT+VTS=[440,350,255]\r\n") #Generate a dial tone
            time_since_last_dial_tone = now

        if time_since_last_digit is not None:
            # We've received some digits, let's answer the call if it's time
            now = datetime.now()
            delta = (now - time_since_last_digit).total_seconds()
            if delta > 2:
                logging.info("Answering call...")
                send_command(modem, "ATH")
                send_command(modem, "ATA")
                logging.info("Call answered!")
                return 0

        char = modem.read(1)
        if not char:
            continue

        if ord(char) == 16:
            #DLE character
            try:
                char = modem.read()
                digit = int(char)
                time_since_last_digit = datetime.now()
                print "%s" % digit
            except (TypeError, ValueError):
                pass

    return 0


if __name__ == '__main__':
    logging.getLogger().setLevel(logging.INFO)
    logging.getLogger().addHandler(logging.StreamHandler())

    if len(sys.argv) > 1 and sys.argv[-1] == "--no-daemon":
        sys.exit(main())

    daemon = Daemon("/tmp/dreampi.pid", main)

    if len(sys.argv) == 2:
        if sys.argv[1] == "start":
            deamon.start()
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
