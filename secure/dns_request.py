from scapy.all import *
# DNS 쿼리 대상 도메인 이름과 목적지 IP 주소 설정
targetName = 'aaaaa.example.com'
dstIP = '10.9.0.53'
# IP 계층 정의
ip = IP(dst=dstIP)
# UDP 계층 정의 (DNS 기본 포트 53)
udp = UDP(dport=53, chksum=0)
# DNS 쿼리 섹션 생성
Qdsec = DNSQR(qname=targetName)
# DNS 헤더 정의
dns = DNS(id=100, qr=0, qdcount=1, qd=Qdsec)
# 최종 패킷 생성 (IP + UDP + DNS)
Requestpkt = ip / udp / dns
# 생성한 패킷을 바이너리 파일로 저장
with open('ip_req.bin', 'wb') as f:
f.write(bytes(Requestpkt))
