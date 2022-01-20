#!/usr/bin/python
from scapy.all import *
def portscanner(x,z):
    x = str(x)
    if (x.find(',') != -1):
        x = x.split(',')
        ports = list(map(int,x))

    elif (x.find('-') != -1):
        x = x.split('-')
        starting_port = int(x[0])
        ending_port = int(x[1])
        ports = list(range(starting_port,ending_port+1))


    else:
        ports = [(int(x))]

    openports = []
    closedports = []
    for each in ports:
        packets = Ether()/IP(dst=z)/TCP(sport=5555, dport=each)
        ans = srp1(packets)
        if (ans[0][TCP].sport == each and ans[0][TCP].flags == 18):
            openports.append(each)
        else:
            closedports.append(each)
    if openports == []:
        pass
    else:
        openports = ",".join(map(str,openports))
        print("OPEN PORTS: " + openports)
    if closedports  == []:
        pass
    else:
        closedports = ",".join(map(str,closedports))
        print("CLOSED Ports: " + closedports)

if __name__ == '__main__':
    scanner = portscanner(input("What ports do you want to scan?"),input("What domain or IP address do you want to scan?"))
