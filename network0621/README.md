# WHS 4기 네트워크보안 과제 소스 코드
PCAP programming
by 6반 김0희

## 내용

### mytcpheader.h
- 헤더파일. ip, tcp 헤더 구조체
- 원본: 멘토님 깃허브 myheader.h
- https://github.com/pwnhyo/network_security_codes/blob/main/Sniffing_Spoofing/C_spoof/myheader.h

ip, tcp에 해당하는 것만 남김

### pcaptcp.c
- 과제 소스코드
- 참고: 멘토님 깃허브 sniff_improved.c
- https://github.com/pwnhyo/network_security_codes/blob/main/Sniffing_Spoofing/C_sniff/sniff_improved.c

출력 형식:
'''
TCP PACKET found

<Ethernet Header>
src mac: 

dst mac: 


<IP Header>
src ip: 

dst ip: 


<TCP Header>
src port: 80 (http)

dst port: (포트번호)

TCP flags: (플래그 목록)

<HTTP Message>
'''

## 컴파일
'''
gcc pcaptcp.c -o pcaptcp -lpcap
'''
