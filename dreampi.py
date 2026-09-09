#!/usr/bin/env python
#dreampi.py_version=202608171113
# from __future__ import absolute_import
# from __future__ import print_function
import atexit
# from typing import List, Optional, Tuple
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
import iptc
import select
import requests
import netifaces
import ipaddress
import hashlib

from dcnow import DreamcastNowService
from port_forwarding import PortForwarding
from datetime import datetime, timedelta

def updater():
    if os.path.isfile("/boot/noautoupdates.txt"):
        logger.info("Dreampi script auto updates are disabled")
        return

    scripts = {
        "netlink.py": "https://raw.githubusercontent.com/eaudunord/Netlink/main/tunnel/netlink.py",
        "dreampi.py": "https://raw.githubusercontent.com/Kazade/dreampi/master/dreampi.py",
        "dcnow.py":   "https://raw.githubusercontent.com/Kazade/dreampi/master/dcnow.py",
    }

    restartFlag = False
    base_path = "/home/pi/dreampi/"

    def sha256(data):
        return hashlib.sha256(data).hexdigest()

    def extract_version(data):
        for line in data.splitlines():
            try:
                line = line.decode("utf-8")
            except Exception:
                continue
            if "_version=" in line:
                try:
                    return int(line.split("version=")[1].strip())
                except ValueError:
                    return None
        return None

    for name, url in scripts.items():
        local_script = os.path.join(base_path, name)

        try:
            # --- Fetch upstream file ---
            r = requests.get(url, timeout=10)
            r.raise_for_status()
            upstream_data = r.content

            upstream_version = extract_version(upstream_data)

            # --- Read local file (if present) ---
            local_data = None
            local_version = None

            if os.path.isfile(local_script):
                with open(local_script, "rb") as f:
                    local_data = f.read()
                local_version = extract_version(local_data)

            # --- Safety checks ---
            if upstream_version is None:
                logger.info("%s has no upstream version; keeping local copy", name)
                continue

            if local_version is None:
                logger.info("%s has no local version; skipping update for safety", name)
                continue

            if local_version >= upstream_version:
                logger.info("%s is up to date (v%s)", name, local_version)
                continue

            # --- Hash check (avoid useless rewrites) ---
            if local_data is not None and sha256(local_data) == sha256(upstream_data):
                logger.info("%s unchanged", name)
                continue

            # --- Write update ---
            with open(local_script, "wb") as f:
                f.write(upstream_data)

            if name == "dreampi.py":
                os.system("sudo chmod +x " + local_script)
                restartFlag = True

            logger.info("%s updated (v%s to v%s)", name, local_version, upstream_version)

        except requests.exceptions.SSLError:
            logger.info("SSL error while checking updates (check system time)")
            return

        except requests.exceptions.RequestException as e:
            logger.info("Failed to update %s: %s", name, e)
            continue

    if restartFlag:
        logger.info("Update applied. Rebooting.")
        os.system("sudo reboot")

DNS_FILE = "https://dreamcast.online/dreampi/dreampi_dns.conf"


logger = logging.getLogger("dreampi")
logger.propagate = False


def check_internet_connection():
    """ Returns True if there's a connection """

    IP_ADDRESS_LIST = [
        "1.1.1.1",  # Cloudflare
        "1.0.0.1",
        "8.8.8.8",  # Google DNS
        "8.8.4.4",
        "208.67.222.222",  # Open DNS
        "208.67.220.220",
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


def restart_dnsmasq():
    subprocess.call("sudo service dnsmasq restart".split())

def fetch_dreampi_updates():
    subprocess.Popen(["python", "/home/pi/dreampi/updater/fetch_updates.py"])

def update_dns_file():
    """
        Download a DNS settings file for the DreamPi configuration (avoids forwarding requests to the main DNS server
        and provides a backup if that ever goes down)
    """
    # check for a remote configuration
    try:
        response = requests.get(DNS_FILE)
        response.raise_for_status()
    except requests.exceptions.HTTPError:
        logging.info(
            "Did not find remote DNS config; will use upstream"
        )
        return
    except requests.exceptions.Timeout:
        logging.info(
            "Request timed out; will use upstream"
        )
        return
    except requests.exceptions.SSLError:
        logging.info(
            "SSL error; will use upstream"
        )
        return

    # Stop the server
    subprocess.check_call("sudo service dnsmasq stop".split())

    # Update the configuration
    try:
        with open("/etc/dnsmasq.d/dreampi.conf", "w") as f:
            f.write(response.read())
    except IOError:
        logging.exception("Found remote DNS config but failed to apply it locally")

    # Start the server again
    subprocess.check_call("sudo service dnsmasq start".split())


# Update dreampi.py if file exists in /boot
def dreampi_py_local_update():
    if os.path.isfile("/boot/dpiupdate.py") == False:
        logger.info("No update file is found in /boot")
        return

    os.system("sudo mv /boot/dpiupdate.py /home/pi/dreampi/dreampi.py")
    os.system("sudo chown pi:pi /home/pi/dreampi/dreampi.py")
    os.system("sudo chmod +x /home/pi/dreampi/dreampi.py")
    logger.info('Updated the dreampi.py from /boot/dpiupdate.py ... Rebooting')
    os.system("sudo reboot")

#
# IPTABLES RULES
#

def iptables_add_if_missing(cmd):
    """
    Add an iptables rule only if it does not already exist.
    Supports -A (append) and -I (insert) commands.

    Example:
        iptables_add_if_missing([
            "iptables", "-t", "mangle", "-I", "FORWARD",
            "-i", "ppp0", "-j", "TTL", "--ttl-set", "64"
        ])
    """

    if "iptables" not in cmd[0]:
        raise ValueError("Command must start with 'iptables'")

    # Determine action type and position
    try:
        action_index = cmd.index("-A")
        action_type = "-A"
    except ValueError:
        try:
            action_index = cmd.index("-I")
            action_type = "-I"
        except ValueError:
            raise ValueError("Command must contain '-A' or '-I'")

    # Build check command by replacing -A/-I with -C
    check_cmd = cmd[:]
    check_cmd[action_index] = "-C"

    try:
        subprocess.check_call(check_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logger.info("Rule already exists, skipping.")
    except subprocess.CalledProcessError:
        logger.info("Rule not found, adding it...")
        subprocess.check_call(cmd)

# Add SNAT and DNAT to the newly created interface
def add_pseudo_interface_rules(dc_ip, tun_ip):

    iptables_add_if_missing([
        "iptables", "-t", "nat", "-I", "POSTROUTING",
        "!", "-o", "tun0",
        "-s", tun_ip,
        "-j", "SNAT",
        "--to-source", dc_ip
    ])

    iptables_add_if_missing([
        "iptables", "-t", "nat", "-I", "PREROUTING",
        "!", "-i", "ppp0",
        "-d", dc_ip,
        "-j", "DNAT",
        "--to-destination", tun_ip
    ])

    logger.info("DC Alias interface rules added")

# Removes SNAT and DNAT to the newly created interface
def remove_pseudo_interface_rules(dc_ip, tun_ip):

    subprocess.call([
        "iptables", "-t", "nat", "-D", "POSTROUTING",
        "!", "-o", "tun0",
        "-s", tun_ip,
        "-j", "SNAT",
        "--to-source", dc_ip
    ])

    subprocess.call([
        "iptables", "-t", "nat", "-D", "PREROUTING",
        "!", "-i", "ppp0",
        "-d", dc_ip,
        "-j", "DNAT",
        "--to-destination", tun_ip
    ])

    logger.info("DC Alias interface rules removed")

# Block INPUT to tun0, only accept ICMP and RELATED,ESTABLISHED
# Accept forward traffic from or to the tun0 to avoid userspace
# fixes to be applied

def add_vpn_rules(tun_ip):

    iptables_add_if_missing([
        "iptables", "-I", "INPUT",
        "-i", "tun0",
        "-d", tun_ip,
        "-j", "DROP"
    ])

    iptables_add_if_missing([
        "iptables", "-I", "INPUT",
        "-i", "tun0",
        "-d", tun_ip,
        "-p", "icmp",
        "-j", "ACCEPT"
    ])

    iptables_add_if_missing([
        "iptables", "-I", "INPUT",
        "-i", "tun0",
        "-d", tun_ip,
        "-p", "tcp",
        "-m", "multiport",
        "--dports", "65432,65433",
        "-m", "state",
        "--state", "NEW",
        "-j", "ACCEPT"
    ])

    iptables_add_if_missing([
        "iptables", "-I", "INPUT",
        "-i", "tun0",
        "-d", tun_ip,
        "-p", "udp",
        "-m", "multiport",
        "--dports", "20001,20002",
        "-m", "state",
        "--state", "NEW",
        "-j", "ACCEPT"
    ])

    iptables_add_if_missing([
        "iptables", "-I", "INPUT",
        "-i", "tun0",
        "-m", "state",
        "--state", "ESTABLISHED,RELATED",
        "-j", "ACCEPT"
    ])

    iptables_add_if_missing([
        "iptables", "-t", "mangle", "-I", "FORWARD",
        "-i", "tun0",
        "-j", "RETURN"
    ])

    iptables_add_if_missing([
        "iptables", "-t", "mangle", "-I", "FORWARD",
        "-o", "tun0",
        "-j", "RETURN"
    ])

    logger.info("DC VPN rules")

def remove_vpn_rules(tun_ip):

    subprocess.call([
        "iptables", "-D", "INPUT",
        "-i", "tun0",
        "-d", tun_ip,
        "-j", "DROP"
    ])

    subprocess.call([
        "iptables", "-D", "INPUT",
        "-i", "tun0",
        "-d", tun_ip,
        "-p", "icmp",
        "-j", "ACCEPT"
    ])

    subprocess.call([
        "iptables", "-D", "INPUT",
        "-i", "tun0",
        "-m", "state",
        "--state", "ESTABLISHED,RELATED",
        "-j", "ACCEPT"
    ])

    subprocess.call([
        "iptables", "-t", "mangle", "-D", "FORWARD",
        "-i", "tun0",
        "-j", "RETURN"
    ])

    subprocess.call([
        "iptables", "-t", "mangle", "-D", "FORWARD",
        "-o", "tun0",
        "-j", "RETURN"
    ])

    subprocess.call([
        "iptables", "-D", "INPUT",
        "-i", "tun0",
        "-d", tun_ip,
        "-p", "tcp",
        "-m", "multiport",
        "--dports", "65432,65433",
        "-m", "state",
        "--state", "NEW",
        "-j", "ACCEPT"
    ])

    subprocess.call([
        "iptables", "-D", "INPUT",
        "-i", "tun0",
        "-d", tun_ip,
        "-p", "udp",
        "-m", "multiport",
        "--dports", "20001,20002",
        "-m", "state",
        "--state", "NEW",
        "-j", "ACCEPT"
    ])

    logger.info("DC VPN rules REMOVED")

# Increase the TTL in the IP HDR from 30 to 64
def add_increased_ttl():
    iptables_add_if_missing([
        "iptables", "-t", "mangle", "-A", "FORWARD",
        "-i", "ppp0",
        "-j", "TTL", "--ttl-set", "64"
    ])

def remove_increased_ttl():
    subprocess.call([
        "iptables", "-t", "mangle", "-D", "FORWARD",
        "-i", "ppp0",
        "-j", "TTL", "--ttl-set", "64"
    ])

# Prevent games like PowerSmash to send double SYN packets
def add_syn_check():
    iptables_add_if_missing([
        "iptables", "-A", "FORWARD",
        "-p", "tcp", "--syn", "--sport", "3200:3205", "-m", "recent", "--name", "syncheck",
        "--rsource", "--rdest", "--update", "--seconds", "1", "--hitcount", "1", "-j", "DROP"
    ])

    iptables_add_if_missing([
        "iptables", "-A", "FORWARD",
        "-p", "tcp", "--syn", "--sport", "3200:3205", "-m", "recent", "--name", "syncheck",
        "--rsource", "--rdest", "--set"
    ])


def remove_syn_check():
    subprocess.call([
        "iptables", "-D", "FORWARD",
        "-p", "tcp", "--syn", "--sport", "3200:3205", "-m", "recent", "--name", "syncheck",
        "--rsource", "--rdest", "--update", "--seconds", "1", "--hitcount", "1", "-j", "DROP"
    ])

    subprocess.call([
        "iptables", "-D", "FORWARD",
        "-p", "tcp", "--syn", "--sport", "3200:3205", "-m", "recent", "--name", "syncheck",
        "--rsource", "--rdest", "--set"
    ])

def is_service_running(name):
    try:
        # Run pgrep -f process_name
        subprocess.check_call(['pgrep', '-f', name],
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        # pgrep returns non-zero if no process is found
        return False

def start_service(name):
    try:
        logger.info("Starting {} process".format(name))
        with open(os.devnull, "wb") as devnull:
            subprocess.check_call(["sudo", "systemctl", "start", name], stdout=devnull)
    except (subprocess.CalledProcessError, IOError):
        logging.warning("Unable to start the {} process".format(name))


def stop_service(name):
    try:
        logger.info("Stopping {} process".format(name))
        with open(os.devnull, "wb") as devnull:
            subprocess.check_call(["sudo", "systemctl", "stop", name], stdout=devnull)
    except (subprocess.CalledProcessError, IOError):
        logging.warning("Unable to stop the {} process".format(name))

#
# IP and INTERFACE functions
#

def get_ip_address(interface):
    try:
        addrs = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addrs:
            ip = addrs[netifaces.AF_INET][0]['addr']
            return ip
        else:
            return None  # No IPv4 address
    except ValueError:
        return None  # Interface not found
def get_default_iface_name_linux():
    route = "/proc/net/route"
    with open(route) as f:
        for line in f.readlines():
            try:
                iface, dest, _, flags, _, _, _, _, _, _, _, = line.strip().split()
                if dest != "00000000" or not int(flags, 16) & 2:
                    continue
                return iface
            except:
                continue


def ip_exists(ip, iface):
    command = ["arp", "-a", "-i", iface]
    output = subprocess.check_output(command).decode()
    if ("(%s)" % ip) in output and 'incomplete' not in output:
        logger.info("IP existed at %s", ip)
        return True
    else:
        logger.info("Free IP at %s", ip)
        return False


def find_next_unused_ip(start):
    interface = get_default_iface_name_linux()

    parts = [int(x) for x in start.split(".")]
    current_check = parts[-1] - 1

    while current_check:
        test_ip = ".".join([str(x) for x in parts[:3] + [current_check]])
        if not ip_exists(test_ip, interface):
            return test_ip
        current_check -= 1

    raise Exception("Unable to find a free IP on the network")

def create_alias_interface(dc_ip, tun_ip):
    interface = get_default_iface_name_linux()
    iface_alias = interface + ":1"
    ip_addr = dc_ip + "/32"

    try:
        with open(os.devnull, "wb") as devnull:
            subprocess.check_call(["sudo", "ip", "addr", "add", ip_addr, "dev", interface, "label", iface_alias], stdout=devnull)
        logger.info("Created alias interface %s with IP %s", iface_alias, ip_addr)
    except subprocess.CalledProcessError as e:
        logging.exception("Error: Could not create alias interface")

    add_pseudo_interface_rules(dc_ip, tun_ip)

def remove_alias_interface():
    interface = get_default_iface_name_linux()
    iface_alias = interface + ":1"
    dc_ip = get_ip_address(iface_alias)
    tun_ip =  get_ip_address("tun0")

    try:
        with open(os.devnull, "wb") as devnull:
            subprocess.check_call(["sudo", "ip", "addr", "flush", "dev", interface, "label", iface_alias], stdout=devnull)
        logger.info("Flushed alias interface %s", iface_alias)
    except subprocess.CalledProcessError as e:
        logging.exception("Error: Could not remove alias interface")

    if dc_ip is not None:
        try:
            with open(os.devnull, "wb") as devnull:
                subprocess.check_call(["sudo", "arp", "-d", dc_ip], stdout=devnull)
            logger.info("Removed ARP entry for %s", dc_ip)
        except subprocess.CalledProcessError:
            logging.error("No ARP entry to remove for %s", dc_ip)

    if dc_ip is not None and tun_ip is not None:
        tun_ip_obj = ipaddress.IPv4Address(unicode(tun_ip,'utf-8'))
        tun_dc_ip = tun_ip_obj + 1
        remove_pseudo_interface_rules(dc_ip, str(tun_dc_ip))

def autoconfigure_ppp(device, speed):
    """
       Every network is different, this function runs on boot and tries
       to autoconfigure PPP as best it can by detecting the subnet and gateway
       we're running on.

       Returns the IP allocated to the Dreamcast
    """

    gateway_ip = subprocess.check_output(
        "route -n | grep 'UG[ \t]' | awk '{print $2}'", shell=True
    ).decode()
    subnet = gateway_ip.split(".")[:3]

    PEERS_TEMPLATE = "{device}\n" "{device_speed}\n" "{this_ip}:{dc_ip}\n" "auth\n"

    OPTIONS_TEMPLATE = "debug\n" "ms-dns {this_ip}\n" "proxyarp\n" "ktune\n" "noccp\n"

    PAP_SECRETS_TEMPLATE = "# Modded from dreampi.py\n" "# INBOUND connections\n" '*       *       ""      *' "\n"

    tun_ip =  get_ip_address("tun0")
    this_ip = find_next_unused_ip(".".join(subnet) + ".100")
    dreamcast_ip = find_next_unused_ip(this_ip)

    # Check if VPN is up and set IPs accordingly
    if tun_ip is not None:
        tun_ip_obj = ipaddress.IPv4Address(unicode(tun_ip,'utf-8'))
        tun_dc_ip = tun_ip_obj + 1
        tun_this_ip = tun_dc_ip + 1
        add_vpn_rules(tun_ip)
        logger.info("TUN detected: tun0: %s ppp0: %s:%s", tun_ip, str(tun_this_ip), str(tun_dc_ip))

        peers_content = PEERS_TEMPLATE.format(
            device=device, device_speed=speed, this_ip=tun_this_ip, dc_ip=tun_dc_ip
        )
        options_content = OPTIONS_TEMPLATE.format(this_ip=dreamcast_ip)
    else:
        logger.info("Dreamcast IP: {}".format(dreamcast_ip))
        peers_content = PEERS_TEMPLATE.format(
            device=device, device_speed=speed, this_ip=this_ip, dc_ip=dreamcast_ip
        )
        options_content = OPTIONS_TEMPLATE.format(this_ip=this_ip)

    with open("/etc/ppp/peers/dreamcast", "w") as f:
        f.write(peers_content)

    with open("/etc/ppp/options", "w") as f:
        f.write(options_content)

    pap_secrets_content = PAP_SECRETS_TEMPLATE

    with open("/etc/ppp/pap-secrets", "w") as f:
        f.write(pap_secrets_content)

    return dreamcast_ip


ENABLE_SPEED_DETECTION = (
    True
)  # Set this to true if you want to use wvdialconf for device detection


def detect_device_and_speed():
    MAX_SPEED = 57600

    if not ENABLE_SPEED_DETECTION:
        # By default we don't detect the speed or device as it's flakey in later
        # Pi kernels. But it might be necessary for some people so that functionality
        # can be enabled by setting the flag above to True
        return ("/dev/ttyACM0", MAX_SPEED)

    command = ["wvdialconf", "/dev/null"]

    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT).decode()

        lines = output.split("\n")

        for line in lines:
            match = re.match(r"(.+)<Info>:\sSpeed\s(\d+);", line.strip())
            if match:
                device = match.group(1)
                speed = int(match.group(2))
                logger.info("Detected device {} with speed {}".format(device, speed))

                # Many modems report speeds higher than they can handle so we cap
                # to 56k
                return "/dev/"+device, min(speed, MAX_SPEED)
        else:
            logger.info("No device detected")

    except:
        logger.exception("Unable to detect modem. Falling back to ttyACM0")
    return ("/dev/ttyACM0", MAX_SPEED)


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
        with open(self.pidfile, "w+") as f:
            f.write("%s\n" % pid)

    def delete_pid(self):
        os.remove(self.pidfile)

    def _read_pid_from_pidfile(self):
        try:
            with open(self.pidfile, "r") as pf:
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


class Modem(object):
    def __init__(self, device, speed, send_dial_tone=True):
        self._device, self._speed = device, speed
        self._serial = None
        self._sending_tone = False

        if send_dial_tone:
            self._dial_tone_wav = self._read_dial_tone()
        else:
            self._dial_tone_wav = None

        self._time_since_last_dial_tone = None
        self._dial_tone_counter = 0

    @property
    def device_speed(self):
        return self._speed

    @property
    def device_name(self):
        return self._device

    def _read_dial_tone(self):
        this_dir = os.path.dirname(os.path.abspath(os.path.realpath(__file__)))
        dial_tone_wav = os.path.join(this_dir, "dial-tone.wav")

        with open(dial_tone_wav, "rb") as f:
            dial_tone = f.read()  # Read the entire wav file
            dial_tone = dial_tone[44:]  # Strip the header (44 bytes)

        return dial_tone

    def connect(self):
        if self._serial:
            self.disconnect()

        logger.info("Opening serial interface to {}".format(self._device))
        self._serial = serial.Serial(
            self._device, self._speed, timeout=0, exclusive=True
        )
        return self._serial

    def connect_netlink(self,speed = 115200, timeout = 0.01, rtscts = False): #non-blocking
        if self._serial:
            self.disconnect()
        logger.info("Opening serial interface to {}".format(self._device))
        self._serial = serial.Serial(
            self._device, speed, timeout=timeout, rtscts = rtscts, exclusive=True
        )

    def disconnect(self):
        if self._serial and self._serial.isOpen():
            self._serial.flush()
            self._serial.close()
            self._serial = None
            logger.info("Serial interface terminated")

    def reset(self):
        while True:
            try:
                self.send_command("ATZ0",timeout=3)  # Send reset command
                time.sleep(1)
                self.send_command("AT&F0")
                self.send_command("ATE0W2")  # Don't echo our responses
                return
            except IOError:
                self.shake_it_off() # modem isn't responding. Try a harder reset

    def start_dial_tone(self):
        if not self._dial_tone_wav:
            return
        i = 0
        while i < 3:
            try:
                self.reset()
                self.send_command(b"AT+FCLASS=8")  # Enter voice mode
                self.send_command(b"AT+VLS=1")  # Go off-hook
                self.send_command(b"AT+VSM=1,8000")  # 8 bit unsigned PCM
                self.send_command(b"AT+VTX")  # Voice transmission mode
                logger.info("<LISTENING>")
                break
            except IOError:
                time.sleep(0.5)
                i+=1
                pass

        self._sending_tone = True

        self._time_since_last_dial_tone = datetime.now() - timedelta(seconds=100)

        self._dial_tone_counter = 0

    def stop_dial_tone(self):
        if not self._sending_tone:
            return
        if self._serial is None:
            raise Exception("Not connected")

        self._serial.write(b"\x00\x10\x03\r\n")
        self.send_escape()
        self.send_command(b"ATH0")  # Go on-hook
        self.reset()  # Reset the modem
        self._sending_tone = False

    def answer(self):
        self.reset()
        # When we send ATA we only want to look for CONNECT. Some modems respond OK then CONNECT
        # and that messes everything up
        self.send_command(b"ATA", ignore_responses=[b"OK"])
        time.sleep(5)
        logger.info("Call answered!")
        logger.info(subprocess.check_output(["pon", "dreamcast"]).decode())
        logger.info("Connected")

    def netlink_answer(self):
        self.reset()
        # When we send ATA we only want to look for CONNECT. Some modems respond OK then CONNECT
        # and that messes everything up
        self.send_command(b"ATA", ignore_responses=[b"OK"])
        # time.sleep(5)
        logger.info("Call answered!")
        logger.info("Connected")

    def query_modem(self, command, timeout=3, response = "OK"): #this function assumes we're being passed a non-blocking modem
        if isinstance(command, bytes):
            final_command = command + b'\r\n'
        else:
            final_command = ("%s\r\n" % command).encode()
        self._serial.write(final_command)
        logger.info(final_command.decode())

        start = time.time()

        line = b""
        while True:
            new_data = self._serial.readline().strip()

            if not new_data: #non-blocking modem will end up here when timeout reached, try until this function's timeout is reached.
                if time.time() - start < timeout:
                    continue
                raise IOError()

            line = line + new_data

            if response.encode() in line:
                if response != "OK":
                    logger.info(line.decode())
                return  # Valid response

    def send_command(
        self, command, timeout=60, ignore_responses = None
    ):
        if self._serial is None:
            raise Exception("Not connected")
        if ignore_responses is None:
            ignore_responses = []

        VALID_RESPONSES = [b"OK", b"ERROR", b"CONNECT", b"VCON"]

        for ignore in ignore_responses:
            VALID_RESPONSES.remove(ignore)

        if isinstance(command, bytes):
            final_command = command + b'\r\n'
        else:
            final_command = ("%s\r\n" % command).encode()

        self._serial.write(final_command)
        logger.info('Command: %s' % command.decode())

        start = time.time()
        line = b""
        while True:
            new_data = self._serial.readline().strip()

            if not new_data:
                if time.time() - start < timeout:
                    continue
                raise IOError("There was a timeout while waiting for a response from the modem")

            line = line + new_data
            for resp in VALID_RESPONSES:
                if resp in line:
                    if resp != b"OK":
                        logger.info('Response: %s' % line.decode())
                        if resp == b"ERROR":
                            raise IOError("Command returned an error")
                    # logger.info(line[line.find(resp) :].decode())
                    return  # We are done


    def send_escape(self):
        if self._serial is None:
            raise Exception("Not connected")
        time.sleep(1.0)
        self._serial.write(b"+++")
        time.sleep(1.0)

    def shake_it_off(self): #sometimes the modem gets stuck in data mode
        for i in range(3):
            self._serial.write(b'+')
            time.sleep(0.2)
        time.sleep(4)
        self.send_command('ATH0') #make sure we're on hook
        logger.info("Shook it off")


    def update(self):
        now = datetime.now()
        if self._sending_tone:
            # Keep sending dial tone
            BUFFER_LENGTH = 1000
            TIME_BETWEEN_UPLOADS_MS = (1000.0 / 8000.0) * BUFFER_LENGTH

            if self._dial_tone_wav is None:
                raise Exception("Dial tone wav not loaded")
            if self._serial is None:
                raise Exception("Not connected")

            if (
                not self._time_since_last_dial_tone
                or ((now - (self._time_since_last_dial_tone)).microseconds * 1000)
                >= TIME_BETWEEN_UPLOADS_MS
            ):
                byte = self._dial_tone_wav[
                    self._dial_tone_counter : self._dial_tone_counter + BUFFER_LENGTH
                ]
                self._dial_tone_counter += BUFFER_LENGTH
                if self._dial_tone_counter >= len(self._dial_tone_wav):
                    self._dial_tone_counter = 0
                self._serial.write(byte)
                self._time_since_last_dial_tone = now


class GracefulKiller(object):
    def __init__(self):
        self.kill_now = False
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

    def exit_gracefully(self, signum, frame):
        logging.warning("Received signal: %s", signum)
        self.kill_now = True


def process():
    import netlink
    killer = GracefulKiller()

    dial_tone_enabled = "--disable-dial-tone" not in sys.argv

    # Make sure pppd isn't running
    with open(os.devnull, "wb") as devnull:
        subprocess.call(["sudo", "killall", "pppd"], stderr=devnull)

    device_and_speed, internet_connected = None, False
    # Startup checks, make sure that we don't do anything until
    # we have a modem and internet connection
    while True:
        logger.info("Detecting connection and modem...")
        internet_connected = check_internet_connection()
        device_and_speed = detect_device_and_speed()

        if internet_connected and device_and_speed:
            logger.info("Internet connected and device found!")
            break

        elif not internet_connected:
            logger.warn("Unable to detect an internet connection. Waiting...")
        elif not device_and_speed:
            logger.warn("Unable to find a modem device. Waiting...")

        time.sleep(5)

    #
    # We have internet start openvpn client here
    #
    start_service("openvpn-client")
    tun_ip, tun_retries = None, 5
    logger.info("Waiting for tun to get established")
    while tun_ip is None:
        tun_ip = get_ip_address("tun0")
        if tun_ip:
            break
        else:
          tun_retries -= 1
          if tun_retries == 0:
              logger.warn("Unable to find tun device. Giving up")
              break
          time.sleep(3)

    # Check if there is any updates, we know the VPN is up now
    # Will only download files not execute them, so dont worry
    fetch_dreampi_updates()

    modem = Modem(device_and_speed[0], device_and_speed[1], dial_tone_enabled)
    dreamcast_ip = autoconfigure_ppp(modem.device_name, modem.device_speed)

    # Get a port forwarding object, now that we know the DC IP.
    if "--enable-port-forwarding" in sys.argv:
        port_forwarding = PortForwarding(dreamcast_ip, logger)
        port_forwarding.forward_all()
    else:
        port_forwarding = None

    mode = "LISTENING"

    modem.connect()
    if dial_tone_enabled:
        modem.start_dial_tone()

    time_digit_heard = None

    netlink = netlink.Netlink(modem)
    dcnow = DreamcastNowService()
    while True:
        if killer.kill_now:
            break

        netlink.poll()

        now = datetime.now()

        if mode == "LISTENING":

            modem.update()
            char = modem._serial.read(1).strip().decode()
            if not char:
                continue

            if ord(char) == 16:
                # DLE character
                try:
                    parsed = netlink.digit_parser()
                    client = parsed['client']
                    dial_string = parsed['dial_string']
                    if client != "idle":
                        logger.info("Heard: %s" % dial_string)
                        logger.info("Mode detected: %s" % client)
                    if client == 'idle':
                        pass
                    elif client == 'PPP':
                        mode = "ANSWERING"
                        modem.stop_dial_tone()
                        time_digit_heard = now
                except (TypeError, ValueError):
                    logger.info("error")
                    pass

        elif mode == "ANSWERING":
            if time_digit_heard is None:
                raise Exception("Impossible code path")
            if (now - time_digit_heard).total_seconds() > 8.0:
                time_digit_heard = None
                try:
                    modem.answer()
                except IOError:
                    logger.info("Couldn't answer call. Going back to listening")
                    modem.start_dial_tone()
                    mode = "LISTENING"
                    continue
                modem.disconnect()
                mode = "CONNECTED"

        elif mode == "CONNECTED":
            tun_ip =  get_ip_address("tun0")
            if tun_ip is not None:
                tun_ip_obj = ipaddress.IPv4Address(unicode(tun_ip,'utf-8'))
                tun_dc_ip = tun_ip_obj + 1
                create_alias_interface(dreamcast_ip, str(tun_dc_ip))

            dcnow.go_online(dreamcast_ip)

            # -F (not -f) so the tail reopens the file by name if logrotate
            # rotates /var/log/messages mid-call. With -f it would keep reading
            # the renamed inode, never see pppd's "Exit." and hang in CONNECTED.
            for line in sh.tail("-F", "/var/log/messages", "-n", "1", _iter=True):
                if "pppd" in line and "Exit" in line:#wait for pppd to execute the ip-down script
                    logger.info("Detected modem hang up, going back to listening")
                    break

            # Flush the IP on the alias interface
            remove_alias_interface()

            dcnow.go_offline() #changed dcnow to wait 15 seconds for event instead of sleeping. Should be faster.
            mode = "LISTENING"
            # modem = Modem(device_and_speed[0], device_and_speed[1], dial_tone_enabled)
            modem.connect()
            time.sleep(1.5)
            for i in range(3): # escape sequence
                modem._serial.write(b'+')
                time.sleep(0.2)
            time.sleep(1.5)
            try:
                modem.query_modem("ATH0")
            except IOError:
                # Modem didn't acknowledge the hang up. Don't take the daemon
                # down over it - start_dial_tone() calls reset(), which will
                # shake_it_off() if the modem is still stuck in data mode.
                logger.warning("No response to ATH0 after hang up, continuing")
            time.sleep(1)
            if dial_tone_enabled:
                modem.start_dial_tone()

    if port_forwarding is not None:
        port_forwarding.delete_all()
    return 0


def enable_prom_mode_on_wlan0():
    """
        The Pi wifi firmware seems broken, we can only get it to work by enabling
        promiscuous mode.

        This is a hack, we just enable it for wlan0 and ignore errors
    """

    try:
        subprocess.check_call("sudo ifconfig wlan0 promisc".split())
        logging.info("Promiscuous mode set on wlan0")
    except subprocess.CalledProcessError:
        logging.info("Attempted to set promiscuous mode on wlan0 but was unsuccessful")
        logging.info("Probably no wifi connected, or using a different device name")


def main():
    try:
        # Don't do anything until there is an internet connection
        while not check_internet_connection():
            logger.info("Waiting for internet connection...")
            time.sleep(3)

        #try auto updates /disabled for now
        updater()

        # Dreampi local update check
        dreampi_py_local_update()

        # Try to update the DNS configuration
        update_dns_file()

        # Hack around dodgy Raspberry Pi things
        enable_prom_mode_on_wlan0()

        # Just make sure everything is fine
        restart_dnsmasq()

        config_server.start()

        add_increased_ttl()
        add_syn_check()

        start_service("dcvoip")
        start_service("dcgamespy")
        start_service("dc2k2")
        start_service("dcdaytona")
        start_service("dcnatrules")

        return process()
    except:
        logger.exception("Something went wrong...")
        return 1
    finally:
        stop_service("dc2k2")
        stop_service("dcgamespy")
        stop_service("dcvoip")
        stop_service("dcdaytona")
        stop_service("dcnatrules")

        tun_ip = get_ip_address("tun0")
        stop_service("openvpn-client")
        remove_alias_interface()

        if tun_ip is not None:
            remove_vpn_rules(tun_ip)

        remove_increased_ttl()
        remove_syn_check()

        config_server.stop()
        logger.info("Dreampi quit successfully")


if __name__ == "__main__":
    logger.setLevel(logging.INFO)
    syslog_handler = logging.handlers.SysLogHandler(address="/dev/log")
    syslog_handler.setFormatter(
        logging.Formatter("%(name)s[%(process)d]: %(levelname)s %(message)s")
    )
    logger.addHandler(syslog_handler)

    if len(sys.argv) > 1 and "--no-daemon" in sys.argv:
        # logger.addHandler(logging.StreamHandler())
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
        print(("Usage: %s start|stop|restart" % sys.argv[0]))
        sys.exit(2)
