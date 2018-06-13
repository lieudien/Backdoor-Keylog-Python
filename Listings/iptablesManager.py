import os, time, threading

def openPort(protocol, ip, port, ttl):
    os.system(addIptablesRule("INPUT", protocol, ip, port))
    os.system(addIptablesRule("OUTPUT", protocol, ip, port))
    print("Added iptables rules")
    
    if ttl > 0:
        time.sleep(ttl)
        os.system(removeIptablesRule("INPUT", protocol, ip, port))
        os.system(removeIptablesRule("OUTPUT", protocol, ip, port))
        print("Iptables rules removed")

def addIptablesRule(type, protocol, ip, port):
    if type == "INPUT":
        return "iptables -A INPUT -p {} --dport {} -s {} -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT".format(protocol, port, ip)
    elif type == "OUTPUT":
        return "iptables -A OUTPUT -p {} --sport {} -d {} -m conntrack --ctstate ESTABLISHED -j ACCEPT".format(protocol, port, ip)

def removeIptablesRule(type, protocol, ip, port):
    if type == "INPUT":
        return "iptables -D INPUT -p {} --dport {} -s {} -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT".format(protocol, port, ip)
    elif type == "OUTPUT":
        return "iptables -D OUTPUT -p {} --sport {} -d {} -m conntrack --ctstate ESTABLISHED -j ACCEPT".format(protocol, port, ip)


if __name__ == '__main__':
    main()
