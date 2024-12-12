from scapy.all import *
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP

# 계층의 목적지 MAC 주소로 설정
MAC_V_real = "02:42:c0:a8:3c:0b"  # 라우터 맥주소
ether = Ether(dst=MAC_V_real)

ip = IP(src="192.168.60.6", dst="10.9.0.255") # IP 주소 설정, 10.9.0.255는 브로드캐스트 주소
icmp = ICMP(type=8)   # 8은 "Echo Request" 핑 요청

frame = ether/ip/icmp # 각 계층을 결합하여 전체 패킷을 구성

sendp(frame, iface='eth0') # eth0를 통해 2계층에서 패킷을 전송
 
 # 192.168.60.6에서 10.9.0.255 브로드캐스트 주소로 향하는 핑 요청 패킷을 생성하고 라우터 MAC 주소로 전송한다.