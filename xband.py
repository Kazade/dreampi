#xband_version=202305141942
import sys

if __name__ == "__main__":
    print("This script should not be run on its own")
    sys.exit()

import socket
import time
from datetime import datetime
import logging
import select
import os
import requests
import subprocess
import errno
import threading

ser = None
osName = os.name
if osName == 'posix':
    logger = logging.getLogger('dreampi')
else:
    logger = logging.getLogger('Xband')
logger.setLevel(logging.INFO)

opponent_port = 4000
opponent_id = "11"
sock_listen = None
my_ip = "127.0.0.1"
try:
    r = requests.get("http://myipv4.p1.opendns.com/get_my_ip")
    r.raise_for_status()
    my_ip = r.json()['ip']
except requests.exceptions.HTTPError:
    logger.info("Couldn't get WAN IP")
    my_ip = "127.0.0.1"

if osName == 'posix': # should work on linux and Mac for USB modem, but untested.
    femtoSipPath = "/home/pi/dreampi/femtosip"
else:
    femtoSipPath = os.path.realpath('./')+"/femtosip"

def openXband():
    PORT = 65433
    global sock_listen
    sock_listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_listen.setblocking(0)
    sock_listen.bind(('', PORT))
    sock_listen.listen(5)
    logger.info("listening for xband call")

def closeXband():
    global sock_listen
    try:
        sock_listen.close()
    except:
        pass



def xbandInit():
    if os.path.exists(femtoSipPath) == False:
        try:
            os.makedirs(femtoSipPath)
            r = requests.get("https://raw.githubusercontent.com/eaudunord/femtosip/master/femtosip.py")
            r.raise_for_status()
            with open(femtoSipPath+"/femtosip.py",'wb') as f:
                text = r.content.decode('ascii','ignore').encode()
                f.write(text)
            logger.info('fetched femtosip')
            r = requests.get("https://github.com/astoeckel/femtosip/raw/master/LICENSE")
            r.raise_for_status()
            with open(femtoSipPath+"/LICENSE",'wb') as f:
                f.write(r.content)
            logger.info('fetched LICENSE')
            with open(femtoSipPath+"/__init__.py",'wb') as f:
                pass
        except requests.exceptions.HTTPError:
            logger.info("unable to fetch femtosip")
            return "dropped"
        except OSError:
            logger.info("error creating femtosip directory")
    else:
        global sip_ring
        import femtosip.femtosip as sip_ring

def xbandListen(modem):
    global sock_listen
    ready = select.select([sock_listen], [], [],0)
    if ready[0]:
        logger.info("incoming xband call")
        conn, addr = sock_listen.accept()
        opponent = addr[0]
        callTime = time.time()
        while True:
            ready = select.select([conn], [], [],0)
            if ready[0]:
                data = conn.recv(1024)
                if data == b"RESET":
                    modem.stop_dial_tone()
                    init_xband(modem)
                    # modem.connect_netlink(speed=57600,timeout=0.05,rtscts=True)
                    # modem.query_modem(b'AT%E0')
                    # modem.query_modem(b"AT\V1%C0")
                    # modem.query_modem(b'AT+MS=V22b')
                    conn.sendall(b'ACK RESET')
                    # time.sleep(2)
                elif data == b"RING":
                    logger.info("RING")
                    # time.sleep(4)
                    conn.sendall(b'ANSWERING')
                    time.sleep(6)
                    logger.info('Answering')
                    modem.query_modem("ATX1D", timeout=120, response = "CONNECT")
                    logger.info("CONNECTED")
                elif data == b"PING":
                    conn.sendall(b'ACK PING')
                    modem._serial.timeout=None
                    modem._serial.write(b'\xff')
                    while True:
                        char = modem._serial.read(1) #read through the buffer and skip all 0xff
                        if char == b'\xff':
                            continue
                        elif char == b'\x01':
                            # modem._serial.write(b'\x01')
                            conn.sendall(b'RESPONSE')
                            logger.info('got a response')
                            break
                    if modem._serial.cd: #if we stayed connected
                        continue
                        
                    elif not modem._serial.cd: #if we dropped the call
                        logger.info("Xband Disconnected")
                        # mode = "LISTENING"
                        modem.connect()
                        modem.start_dial_tone()
                        return ("dropped","")
                    
                elif data == b'RESPONSE':
                    modem._serial.write(b'\x01')
                    if modem._serial.cd:
                        return ("connected",opponent)
                if time.time() - callTime > 120:
                    break
    return ("nothing","")
                    
def ringPhone(oppIP,modem):
    import femtosip.femtosip as sip_ring
    opponent = oppIP
    PORT = 65433
    sock_send = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_send.settimeout(15)
    logger.info("Calling opponent")
    # time.sleep(8)
    
    # sip = femtosip.SIP(user, password, gateway, port, display_name)
    # sip.call(call, delay)

    try:
        sock_send.connect((opponent, PORT))
        sock_send.sendall(b"RESET")
        sentCall = time.time()
        while True:
            ready = select.select([sock_send], [], [],0)
            if ready[0]:
                data = sock_send.recv(1024)
                if data == b'ACK RESET':
                    sip = sip_ring.SIP('user','',opponent,opponent_port,local_ip = my_ip,protocol="udp")
                    sip.call(opponent_id,3)
                    sock_send.sendall(b'RING')
                elif data == b'ANSWERING':
                    logger.info("Answering")
                    modem.query_modem("ATA", timeout=120, response = "CONNECT")
                    logger.info("CONNECTED")
                    sock_send.sendall(b'PING')

                elif data == b"ACK PING":
                    modem._serial.timeout=None
                    modem._serial.write(b'\xff')
                    while True:
                        char = modem._serial.read(1) #read through the buffer and skip all 0xff
                        if char == b'\xff':
                            continue
                        elif char == b'\x01':
                            # modem._serial.write(b'\x01')
                            logger.info("got a response")
                            sock_send.sendall(b'RESPONSE')
                            break
                    if modem._serial.cd: #if we stayed connected
                        continue
                        
                    elif not modem._serial.cd: #if we dropped the call
                        return "hangup"

                elif data == b'RESPONSE':
                    modem._serial.write(b'\x01')
                    return opponent
            if time.time() - sentCall > 90:
                logger.info("opponent tunnel not responding")
                return "hangup"


    except socket.error:
        logger.info("couldn't connect to opponent")
        return "hangup"
    
def getserial():
    cpuserial = b"0000000000000000"
    if osName == 'posix':
        try:
            f = open('/proc/cpuinfo','r')
            for line in f:
                if line[0:6]=='Serial':
                    cpuserial = line[10:26].encode()
            f.close()
            logger.info("Found valid CPU ID")
        except:
            cpuserial = b"ERROR000000000"
            logger.info("Couldn't find valid CPU ID, using error ID")
    else:
        cpuserial = subprocess.check_output(["wmic","cpu","get","ProcessorId","/format:csv"]).strip().split(b",")[-1]
        logger.info("Found valid CPU ID")
    return cpuserial
    
def xbandServer(modem):
    modem._serial.timeout = 1
    logger.info("connecting to retrocomputing.network")
    s = socket.socket()
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.setblocking(False)
    s.settimeout(15)
    s.connect(("xbserver.retrocomputing.network", 56969))
    # cpu = subprocess.check_output(["wmic","cpu","get","ProcessorId","/format:csv"]).strip().split(b",")[-1]
    hwid = getserial()
    sdata = b"///////PI-" + hwid + b"\x0a"
    sentid = 0
    logger.info("connected")
    while True:
        try:
            ready = select.select([s], [], [],0.3)
            if ready[0]:
                data = s.recv(1024)
                # print(data)
                modem._serial.write(data)
            if sentid == 0:
                s.send(sdata)
                sentid = 1
        except socket.error as e:
            err = e.args[0]
            if err == errno.EAGAIN or err == errno.EWOULDBLOCK:
                time.sleep(0.1)
            else:
                logger.warn("tcp connection dropped")
                break
        if not modem._serial.cd:
            logger.info("1: CD is not asserted")
            time.sleep(2.0)
            if not modem._serial.cd:
                logger.info("CD still not asserted after 2 sec - xband hung up")
                break
        if sentid == 1:        
            if modem._serial.in_waiting:
                line = b""
                while True:
                    data2 = modem._serial.read(1)
                    line += data2
                    if b"\x10\x03" in line:
                        # print(line)
                        s.send(line)
                        break
                    if not modem._serial.cd:
                        logger.info("2: CD is not asserted")
                        time.sleep(2.0)
                        if not modem._serial.cd:
                            logger.info("CD still not asserted after 2 sec - xband hung up")
                            break
    s.close()
    logger.info("Xband disconnected. Back to listening")
    return

def netlink_exchange(side,net_state,opponent,ser=ser):
    packetSplit = b"<packetSplit>"
    dataSplit = b"<dataSplit>"
    def listener():
        logger.info(state)
        pingCount = 0
        lastPing = 0
        ping = time.time()
        pong = time.time()
        jitterStore = []
        pingStore = []
        currentSequence = 0
        maxPing = 0
        maxJitter = 0
        recoveredCount = 0
        first = True
        if side == "waiting":
            oppPort = 20002
        if side == "calling":
            oppPort = 20001
        while(state != "netlink_disconnected"):
            ready = select.select([udp],[],[],0) #polling select
            if ready[0]:
                # if first == True:
                #     time.sleep(0.01)
                #     first = False
                packetSet = udp.recv(1024)
                
                #start pinging code block
                # if pinging == True:
                #     pingCount +=1
                #     if pingCount >= 30:
                #         pingCount = 0
                #         ping = time.time()
                #         udp.sendto(b'PING_SHIRO', (opponent,oppPort))
                #     if packetSet == b'PING_SHIRO':
                #         udp.sendto(b'PONG_SHIRO', (opponent,oppPort))
                #         continue
                #     elif packetSet == b'PONG_SHIRO':
                #         pong = time.time()
                #         pingResult = round((pong-ping)*1000,2)
                #         if pingResult > 500:
                #             continue
                #         if pingResult > maxPing:
                #             maxPing = pingResult
                #         pingStore.insert(0,pingResult)
                #         if len(pingStore) > 20:
                #             pingStore.pop()
                #         jitter = round(abs(pingResult-lastPing),2)
                #         if jitter > maxJitter:
                #             maxJitter = jitter
                #         jitterStore.insert(0,jitter)
                #         if len(jitterStore) >20:
                #             jitterStore.pop()
                #         jitterAvg = round(sum(jitterStore)/len(jitterStore),2)
                #         pingAvg = round(sum(pingStore)/len(pingStore),2)
                #         if osName != 'posix':
                #             sys.stdout.write('Ping: %s Max: %s | Jitter: %s Max: %s | Avg Ping: %s |  Avg Jitter: %s | Recovered Packets: %s         \r' % (pingResult,maxPing,jitter, maxJitter,pingAvg,jitterAvg,recoveredCount))
                #         lastPing = pingResult
                #         continue
                #end pinging code block

                packets= packetSet.split(packetSplit)
                try:
                    while True:
                        packetNum = 0
                        
                        #go through all packets 
                        for p in packets:
                          if int(p.split(dataSplit)[1]) == currentSequence:
                            break
                          packetNum += 1
                        
                        #if the packet needed is not here,  grab the latest in the set
                        if packetNum == len(packets):
                            packetNum = 0
                        if packetNum > 0 :
                            recoveredCount += 1
                        message = packets[packetNum]
                        payload = message.split(dataSplit)[0]
                        sequence = message.split(dataSplit)[1]
                        if int(sequence) < currentSequence:
                            break  #All packets are old data, so drop it entirely
                        
                        currentSequence = int(sequence) + 1
                        
                        toSend = payload
                        if len(toSend) > 0:
                            ser.write(toSend)
                        # time.sleep(0.016)
                        if packetNum == 0: # if the first packet was the processed packet,  no need to go through the rest
                            break

                except IndexError:
                    continue
                    
        logger.info("listener stopped")        
                
    def sender(side,opponent):
        global state
        logger.info("sending")
        first_run = False
        if side == "waiting":
            oppPort = 20002
        if side == "calling":
            oppPort = 20001
        last = 0
        sequence = 0
        packets = []
        ser.timeout = None #Option 1
        # ser.timeout = 0.01 #Option 2
        
        while(state != "netlink_disconnected"):
            new = ser.read(1) #Option 1
            # if len(new) == 0:
            #     continue
            # if ser.in_waiting > 0: #pings are single bytes. If there are no more bytes, let's assume it's a ping
            #     raw_input = new + ser.read(3) #packets should be 4 bytes. Let's form a full packet.
            # else:
            #     raw_input = new
            raw_input = new + ser.read(ser.in_waiting) #Option1
            # raw_input = ser.read(4) #Option 2
            # if len(raw_input) >1 and len(raw_input) < 4:
            #     print(raw_input)
            if not ser.cd:
                print('')
                logger.info("NO CARRIER")
                ser.read(ser.in_waiting)
                ser.read(ser.in_waiting)
                state = "netlink_disconnected"
                time.sleep(1)
                udp.close()
                logger.info("sender stopped")
                return
            
            try:
                payload = raw_input
                seq = str(sequence)
                if len(payload)>0:
                    
                    packets.insert(0,(payload+dataSplit+seq.encode()))
                    if(len(packets) > 5):
                        packets.pop()
                        
                    for i in range(2): #send the data twice. May help with drops or latency    
                        ready = select.select([],[udp],[]) #blocking select  
                        if ready[1]:
                            udp.sendto(packetSplit.join(packets), (opponent,oppPort))
                                
                    sequence+=1
            except:
                continue

    global state 
    state = net_state              
    if state == "connected":
        t1 = threading.Thread(target=listener)
        t2 = threading.Thread(target=sender,args=(side,opponent))
        if side == "waiting": #we're going to bind to a port. Some users may want to run two instances on one machine, so use different ports for waiting, calling
            Port = 20001
        if side == "calling":
            Port = 20002
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.setblocking(0)
        udp.bind(('', Port))
        
        t1.start()
        t2.start()
        t1.join()
        t2.join()


def init_xband(modem):
        modem.connect_netlink(speed=57600,timeout=0.05,rtscts=True)
        modem.query_modem(b'AT%E0')
        modem.query_modem(b"AT\V1%C0")
        modem.query_modem(b'AT+MS=V22b')