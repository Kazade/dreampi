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
import signal
import re
import struct

from datetime import datetime, timedelta


logger = logging.getLogger('dreampi')


def autoconfigure_ppp(device, speed):
    """
       Every network is different, this function runs on boot and tries
       to autoconfigure PPP as best it can by detecting the subnet and gateway
       we're running on
    """

    PEERS_TEMPLATE = """
{device}
{device_speed}
{this_ip}:{dc_ip}
noauth
    """.strip()

    gateway_ip = subprocess.check_output("route -n | grep 'UG[ \t]' | awk '{print $2}'", shell=True)

    this_ip = "{}.{}.{}.100".format(*gateway_ip.split(".")[:3])
    dreamcast_ip = "{}.{}.{}.101".format(*gateway_ip.split(".")[:3])

    peers_content = PEERS_TEMPLATE.format(device=device, device_speed=speed, this_ip=this_ip, dc_ip=dreamcast_ip)

    with open("/etc/ppp/peers/dreamcast", "w") as f:
        f.write(peers_content)


def detect_device_and_speed():
    command = [ "wvdialconf", "/dev/null" ]

    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT)

        lines = output.split("\n")

        for line in lines:
            match = re.match("(.+)\<Info\>\:\sSpeed\s(\d+);", line.strip())
            if match:
                device = match.group(1)
                speed = match.group(2)
                logger.info("Detected device {} with speed {}".format(device, speed))
                return device, speed
        else:
            logger.info("No device detected")

    except OSError:
        logger.warning("Unable to detect modem. Falling back to ttyACM0")
    return ("ttyACM0", 460800)


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


MODEM_DEVICE = None
DEVICE_SPEED = None
COMM_SPEED = 115200

def connect_to_modem():
    global MODEM_DEVICE
    global DEVICE_SPEED

    if not MODEM_DEVICE:
        MODEM_DEVICE, DEVICE_SPEED = detect_device_and_speed()

    logger.info("Connecting to modem...")

    dev = serial.Serial("/dev/" + MODEM_DEVICE, COMM_SPEED, timeout=0)

    logger.info("Connected.")
    return dev


def send_command(modem, command):
    final_command = "%s\r\n" % command
    modem.write(final_command)
    logger.info(final_command)

    line = modem.readline()
    while True:
        if "OK" in line or "ERROR" in line or "CONNECT" in line or "VCON" in line:
            logger.info(line)
            break

        line = modem.readline()


def boot(dial_tone_enabled):
    # Make sure pppd isn't running
    with open(os.devnull, 'wb') as devnull:
        subprocess.call(["sudo", "killall", "pppd"], stderr=devnull)

    modem = connect_to_modem()

    # Send the initialization string to the modem
    send_command(modem, "ATZE1") # RESET
    send_command(modem, "AT+FCLASS=8")  # Switch to Voice mode
    send_command(modem, "AT+VLS=1") # Go online

    if dial_tone_enabled:
        logger.info("Dial tone enabled, starting transmission...")
        send_command(modem, "AT+VSM=1,8000") # 8 bit, unsigned PCM at 8000hz
        send_command(modem, "AT+VTX") # Transmit audio (for dial tone)

    logger.info("Setup complete, listening...")

    return modem


def process():
    dial_tone_enabled = not "--disable-dial-tone" in sys.argv
    modem = boot(dial_tone_enabled)

    autoconfigure_ppp(MODEM_DEVICE, DEVICE_SPEED) # By this point, MODEM_DEVICE has been set

    this_dir = os.path.dirname(os.path.abspath(os.path.realpath(__file__)))
    dial_tone_wav = os.path.join(this_dir, "dial-tone.wav")

    with open(dial_tone_wav, "rb") as f:
        dial_tone = f.read() # Read the entire wav file
        dial_tone = dial_tone[44:] # Strip the header (44 bytes)

    time_since_last_digit = None
    time_since_last_dial_tone = datetime.now() - timedelta(seconds=100)

    mode = "LISTENING"

    dial_tone_counter = 0
    while True:
        if mode == "LISTENING":
            now = datetime.now()

            if time_since_last_digit is not None:
                # We've received some digits, let's answer the call if it's time
                now = datetime.now()
                delta = (now - time_since_last_digit).total_seconds()
                if delta > 1:
                    if dial_tone_enabled:
                        modem.write("\0{}{}\r\n".format(chr(0x10), chr(0x03)))
                        time.sleep(1.2)
                        modem.write("+++")
                        time.sleep(1.2)

                    logger.info("Answering call...")
                    send_command(modem, "ATH0")
                    send_command(modem, "AT+VLS=0")
                    send_command(modem, "ATZ0")
                    send_command(modem, "AT+FCLASS=0")

                    # Just give the modem a chance to breath...
                    time.sleep(1.0)

                    #send_command(modem, "AT+VLS=1") # Go online
                    send_command(modem, "ATA")
                    logger.info("Call answered!")
                    logger.info(subprocess.check_output(["pon", "dreamcast"]))
                    logger.info("Connected")
                    mode = "CONNECTED"
                    continue

            if dial_tone_enabled:
                # Keep sending dial tone
                BUFFER_LENGTH = 1000
                TIME_BETWEEN_UPLOADS_MS = (1000.0 / 8000.0) * BUFFER_LENGTH

                milliseconds = (now - time_since_last_dial_tone).microseconds * 1000
                if not time_since_last_dial_tone or milliseconds >= TIME_BETWEEN_UPLOADS_MS:
                    byte = dial_tone[dial_tone_counter:dial_tone_counter+BUFFER_LENGTH]
                    dial_tone_counter += BUFFER_LENGTH
                    if dial_tone_counter >= len(dial_tone):
                        dial_tone_counter = 0
                    modem.write(byte)
                    time_since_last_dial_tone = now

            char = modem.read(1).strip()
            if not char:
                continue

            if ord(char) == 16:
                #DLE character
                try:
                    char = modem.read()
                    digit = int(char)

                    time_since_last_digit = datetime.now()
                    logger.info("Heard: %s", digit)
                except (TypeError, ValueError):
                    pass



        elif mode == "CONNECTED":
            # We start watching /var/log/messages for the hang up message
            for line in sh.tail("-f", "/var/log/messages", "-n", "1", _iter=True):
                if "Modem hangup" in line:
                    logger.info("Detected modem hang up, going back to listening")
                    time.sleep(5) # Give the hangup some time
                    mode = "LISTENING"
                    modem.close()
                    dial_tone_enabled = not "--disable-dial-tone" in sys.argv
                    modem = boot(dial_tone_enabled) # Reset the modem
                    time_since_last_digit = None
                    break

    return 0


def main():
    try:
        return process()
    except:
        logger.exception("Something went wrong...")
        return 1


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
