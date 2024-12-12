import socket

udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # socket.AF_INET : IPv4 주소 체계 사용
                                                        # socket.SOCK_DGRAM : UDP 소켓 사용
udp.bind(("0.0.0.0", 9090)) # 모든 네트워크 인터페이스에서 9090 포트로 들어오는 패킷을 수신

while True: # 프로그램 종료할때까지 수신 대기
    data, (ip, port) = udp.recvfrom(1024) # 1024바이트까지의 데이터를 기다리며 수신
    print("From {}:{} {}".format(ip, port, str(data, 'utf8')))
            # 수신된 (송신자의)IP 주소 및 포트, 데이터(바이트 데이터를 UTF-8 문자열로 변환) 출력
    udp.sendto(b'Thank you!\n', (ip, port))
            # 응답 메시지('Thank you!\n')를 바이트 형식으로 설정하여, 수신자에게 전송