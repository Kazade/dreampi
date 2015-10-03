#!/usr/bin/env python

import atexit
import serial
import os
import logging
import logging.handlers
import sys
import time
import subprocess
import sh

from datetime import datetime, timedelta


logger = logging.getLogger('dreampi')


MODEM_DEVICE = "ttyACM0"


class Daemon(object):
    def __init__(self, pidfile, process):
        self.pidfile = pidfile
        self.process = process

    def daemonize(self):
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
    logger.info("Connecting to modem...")

    dev = serial.Serial("/dev/" + MODEM_DEVICE, 460800, timeout=0)

    logger.info("Connected.")
    return dev


def send_command(modem, command):
    final_command = "%s\r\n" % command
    modem.write(final_command)
    logger.info(final_command)

    line = modem.readline()
    while True:
        if "OK" in line or "ERROR" in line or "CONNECT" in line:
            logger.info(line)
            break

        line = modem.readline()


def boot():
    # Make sure pppd isn't running
    subprocess.call(["sudo", "killall", "pppd"])

    modem = connect_to_modem()

    # Send the initialization string to the modem
    send_command(modem, "ATZE1") # RESET
    send_command(modem, "AT+FCLASS=8")  # Switch to Voice mode
    send_command(modem, "AT+VLS=1") # Go online

    if "--enable-dial-tone" in sys.argv:
        print("Dial tone enabled, starting transmission...")
        send_command(modem, "AT+VTX=1") # Transmit audio (for dial tone)

    logger.info("Setup complete, listening...")

    return modem

def main():
    modem = boot()

    this_dir = os.path.dirname(os.path.abspath(os.path.realpath(__file__)))
    dial_tone_wav = os.path.join(this_dir, "dial-tone.wav")

    with open(dial_tone_wav, "rb") as f:
        dial_tone = f.read() # Read the entire wav file
        dial_tone = dial_tone[44:] # Strip the header (44 bytes)

    time_since_last_digit = None
    time_since_last_dial_tone = datetime.now() - timedelta(seconds=3)

    mode = "LISTENING"

    dial_tone_counter = 0

    while True:
        if mode == "LISTENING":
            now = datetime.now()
            delta_seconds = (now - time_since_last_dial_tone).total_seconds()
            if delta_seconds >= 2.55:
    #            modem.write("AT+VTS=[440,350,255]\r\n") #Generate a dial tone
                time_since_last_dial_tone = now

            if time_since_last_digit is not None:
                # We've received some digits, let's answer the call if it's time
                now = datetime.now()
                delta = (now - time_since_last_digit).total_seconds()
                if delta > 2:
                    logger.info("Answering call...")
                    send_command(modem, "ATH")
                    send_command(modem, "ATA")
                    logger.info("Call answered!")
                    subprocess.check_call(["pon", "dreamcast"])
                    logger.info("Connected")
                    mode = "CONNECTED"

            char = modem.read(1).strip()
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

            if "--enable-dial-tone" in sys.argv:
                # Keep sending dial tone
                byte = dial_tone[dial_tone_counter]
                dial_tone_counter += 1
                if dial_tone_counter == len(dial_tone):
                    dial_tone_counter = 0
                modem.write(byte)

        elif mode == "CONNECTED":
            # We start watching /var/log/messages for the hang up message
            for line in sh.tail("-f", "/var/log/messages", "-n", "1", _iter=True):
                if "Modem hangup" in line:
                    logger.info("Detected modem hang up, going back to listening")
                    time.sleep(5) # Give the hangup some time
                    mode = "LISTENING"
                    modem.close()
                    modem = boot() # Reset the modem
                    time_since_last_digit = None
                    break

    return 0


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
