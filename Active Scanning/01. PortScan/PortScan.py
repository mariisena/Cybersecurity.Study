from scapy.all import *
import ipaddress

ports = [25,80,53,443,445,8080,8443]

def SynScan(host):
    print(f"\nIniciando SYN Scan em {host}...")
    ans,unans = sr(
        IP(dst=host)/
        TCP(sport=33333,dport=ports,flags="S")
        ,timeout=2,verbose=0)
    
    print("Portas abertas em %s:" % host)
    for (s,r) in ans:
        if s[TCP].dport == r[TCP].sport and r[TCP].flags=="SA":
            print(f"  Porta {s[TCP].dport} - ABERTA")

def DNSScan(host):
    print(f"\nTestando servidor DNS...")
    ans,unans = sr(
        IP(dst=host)/
        UDP(dport=53)/
        DNS(rd=1,qd=DNSQR(qname="google.com"))
        ,timeout=2,verbose=0)
    
    if ans and ans[UDP]:
        print("  Servidor DNS detectado")

host = input("Digite o IP: ")
try:
    ipaddress.ip_address(host)
except:
    print("IP invalido")
    exit(-1)

SynScan(host)
DNSScan(host)