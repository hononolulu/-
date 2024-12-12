from scapy.all import *

ip = IP(src="192.168.60.6", dst="10.9.0.6") #  IP 계층 출발지 IP 주소와 목적지 IP 주소 설정
udp = UDP(sport=9090, dport=9090) # UDP 계층 출발지 포트와 목적지 포트 설정
data = "Let the PingPong game start ! \n" # 데이터
pkt = ip/udp/data # 전체 패킷

send(pkt, verbose=0, iface='eth0') # 패킷을 eth0 네트워크 인터페이스로 전송(verbose=0은 전송 시 출력 메시지를 최소화하는 옵션)
