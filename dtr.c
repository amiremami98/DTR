#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <curses.h>
#include <time.h>
#include <math.h>
#include <sys/time.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <net/if.h>
#include <getopt.h>

#define PROTO_EXP 253  // Experimental protocol for raw IP

volatile int stop_running = 0;
int max_reached_hop = 0;
int target_hop = 30;

struct hop {
    int sent;
    int recv;
    double last;
    char addr[INET_ADDRSTRLEN];
    double rtts[500];
    int rtt_count;
};

struct hop *hops;
double interval = 0.1;
int max_hops = 30;
char *dst_ip_str;
struct in_addr dst_ip;
char my_ip_str[INET_ADDRSTRLEN];
struct in_addr my_ip;
int send_sock, icmp_sock, l4_sock = -1;
char *protocol;
int dport = -1;
char *payload_type;
char *payload_str;
char *payload_bytes;
size_t payload_len;
int l4_proto;
int is_dns = 0;

struct dnshdr {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

uint16_t checksum(const void *data, size_t len) {
    const uint8_t *buf = data;
    uint32_t sum = 0;
    while (len > 1) {
        sum += *(uint16_t *)buf;
        buf += 2;
        len -= 2;
    }
    if (len) sum += *buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

char *encode_domain(const char *dom) {
    size_t dom_len = strlen(dom);
    char *buf = malloc(dom_len + 2);
    if (!buf) return NULL;
    char *p = buf;
    const char *q = dom;
    while (*q) {
        const char *dot = strchr(q, '.');
        if (!dot) dot = q + strlen(q);
        size_t seg_len = dot - q;
        *p++ = (char)seg_len;
        memcpy(p, q, seg_len);
        p += seg_len;
        q = dot;
        if (*q) q++;
    }
    *p++ = 0;
    return buf;
}

int get_local_ip(char *ip_buf) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;
    struct sockaddr_in serv_addr = {0};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &serv_addr.sin_addr);
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        close(sock);
        return -1;
    }
    struct sockaddr_in local_addr;
    socklen_t addr_len = sizeof(local_addr);
    if (getsockname(sock, (struct sockaddr *)&local_addr, &addr_len) < 0) {
        close(sock);
        return -1;
    }
    inet_ntop(AF_INET, &local_addr.sin_addr, ip_buf, INET_ADDRSTRLEN);
    close(sock);
    return 0;
}

void sigint_handler(int sig) {
    stop_running = 1;
}

void send_probe(int ttl, struct in_addr dst) {
    struct hop *hop = &hops[ttl];
    hop->sent++;

    uint16_t probe_id = rand() & 0xFFFF;
    uint16_t sport = (rand() % (65535 - 1024)) + 1024;

    size_t l4_hdr_len = 0;
    if (strcmp(protocol, "udp") == 0) {
        l4_hdr_len = sizeof(struct udphdr);
    } else if (strcmp(protocol, "tcp") == 0) {
        l4_hdr_len = sizeof(struct tcphdr);
    }

    char *custom_data = payload_bytes;
    size_t data_len = payload_len;

    if (is_dns) {
        char *qname = encode_domain(payload_str);
        if (!qname) return;
        size_t qname_len = strlen(payload_str) + 2;
        size_t dns_len = sizeof(struct dnshdr) + qname_len + 4;
        char *dns_packet = malloc(dns_len);
        if (!dns_packet) {
            free(qname);
            return;
        }
        struct dnshdr *dns = (struct dnshdr *)dns_packet;
        char *qdata = dns_packet + sizeof(struct dnshdr);
        dns->id = htons(rand() & 0xFFFF);
        dns->flags = htons(0x0100); // RD=1
        dns->qdcount = htons(1);
        memcpy(qdata, qname, qname_len);
        *(uint16_t *)(qdata + qname_len) = htons(1); // qtype A
        *(uint16_t *)(qdata + qname_len + 2) = htons(1); // qclass IN
        free(qname);
        custom_data = dns_packet;
        data_len = dns_len;
    }

    size_t l4_len = l4_hdr_len + data_len;
    size_t ip_len = sizeof(struct iphdr) + l4_len;

    char *packet = malloc(ip_len);
    if (!packet) {
        if (is_dns) free(custom_data);
        return;
    }
    memset(packet, 0, ip_len);

    struct iphdr *ip = (struct iphdr *)packet;
    void *l4 = (void *)(packet + sizeof(struct iphdr));
    char *data = (char *)l4 + l4_hdr_len;

    // IP header
    ip->version = 4;
    ip->ihl = 5;
    ip->ttl = ttl;
    ip->protocol = l4_proto;
    ip->saddr = my_ip.s_addr;
    ip->daddr = dst.s_addr;
    ip->tot_len = htons(ip_len);
    ip->id = htons(probe_id);
    ip->check = checksum(packet, sizeof(struct iphdr));

    // Payload
    memcpy(data, custom_data, data_len);

    // L4 header
    if (strcmp(protocol, "udp") == 0) {
        struct udphdr *udp = (struct udphdr *)l4;
        udp->source = htons(sport);
        udp->dest = htons(dport);
        udp->len = htons(l4_len);
        // UDP checksum
        struct {
            uint32_t src_addr;
            uint32_t dst_addr;
            uint8_t placeholder;
            uint8_t protocol;
            uint16_t udp_len;
        } ps_hdr = {ip->saddr, ip->daddr, 0, IPPROTO_UDP, udp->len};
        size_t ps_len = sizeof(ps_hdr) + ntohs(udp->len);
        char *ps_buf = malloc(ps_len);
        if (!ps_buf) {
            free(packet);
            if (is_dns) free(custom_data);
            return;
        }
        memcpy(ps_buf, &ps_hdr, sizeof(ps_hdr));
        memcpy(ps_buf + sizeof(ps_hdr), udp, ntohs(udp->len));
        udp->check = checksum(ps_buf, ps_len);
        free(ps_buf);
    } else if (strcmp(protocol, "tcp") == 0) {
        struct tcphdr *tcp = (struct tcphdr *)l4;
        tcp->source = htons(sport);
        tcp->dest = htons(dport);
        tcp->seq = htonl(rand());
        tcp->ack_seq = 0;
        tcp->doff = 5;
        tcp->syn = 1;
        tcp->window = htons(65535);
        // TCP checksum
        struct {
            uint32_t src_addr;
            uint32_t dst_addr;
            uint8_t placeholder;
            uint8_t protocol;
            uint16_t tcp_len;
        } ps_hdr = {ip->saddr, ip->daddr, 0, IPPROTO_TCP, htons(l4_len)};
        size_t ps_len = sizeof(ps_hdr) + l4_len;
        char *ps_buf = malloc(ps_len);
        if (!ps_buf) {
            free(packet);
            if (is_dns) free(custom_data);
            return;
        }
        memcpy(ps_buf, &ps_hdr, sizeof(ps_hdr));
        memcpy(ps_buf + sizeof(ps_hdr), tcp, l4_len);
        tcp->check = checksum(ps_buf, ps_len);
        free(ps_buf);
    }

    // Send
    struct sockaddr_in dst_addr = {0};
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_addr = dst;
    sendto(send_sock, packet, ip_len, 0, (struct sockaddr *)&dst_addr, sizeof(dst_addr));

    free(packet);
    if (is_dns) free(custom_data);

    // Receive with timeout 1s
    struct timeval sent_time;
    gettimeofday(&sent_time, NULL);

    char buf[1024];
    struct sockaddr_in from;
    socklen_t fromlen;
    while (1) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(icmp_sock, &fds);
        if (l4_sock != -1) FD_SET(l4_sock, &fds);
        int maxfd = (icmp_sock > l4_sock ? icmp_sock : l4_sock) + 1;

        struct timeval curr_time;
        gettimeofday(&curr_time, NULL);
        long sec_diff = curr_time.tv_sec - sent_time.tv_sec;
        long usec_diff = curr_time.tv_usec - sent_time.tv_usec;
        if (usec_diff < 0) {
            usec_diff += 1000000;
            sec_diff--;
        }
        long elapsed_ms = sec_diff * 1000 + usec_diff / 1000;
        if (elapsed_ms >= 1000) break;

        struct timeval rem_tv = {0, (1000 - elapsed_ms) * 1000};
        int sel = select(maxfd, &fds, NULL, NULL, &rem_tv);
        if (sel <= 0) break;

        fromlen = sizeof(from);
        if (FD_ISSET(icmp_sock, &fds)) {
            ssize_t len = recvfrom(icmp_sock, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
            if (len < sizeof(struct iphdr) + sizeof(struct icmphdr)) continue;
            struct iphdr *rip = (struct iphdr *)buf;
            struct icmphdr *icmp = (struct icmphdr *)(buf + rip->ihl * 4);
            if (icmp->type != ICMP_TIME_EXCEEDED && icmp->type != ICMP_DEST_UNREACH) continue;
            char *payload = (char *)icmp + sizeof(struct icmphdr);
            ssize_t pay_len = len - (rip->ihl * 4 + sizeof(struct icmphdr));
            size_t min_pay = sizeof(struct iphdr) + l4_hdr_len;
            if (pay_len < min_pay) continue;
            struct iphdr *oip = (struct iphdr *)payload;
            if (ntohs(oip->id) != probe_id || oip->saddr != my_ip.s_addr || oip->daddr != dst_ip.s_addr || oip->protocol != l4_proto) continue;
            if (l4_sock != -1) {
                void *ol4 = payload + oip->ihl * 4;
                uint16_t osport, odport;
                if (strcmp(protocol, "udp") == 0) {
                    struct udphdr *oudp = (struct udphdr *)ol4;
                    osport = ntohs(oudp->source);
                    odport = ntohs(oudp->dest);
                } else {
                    struct tcphdr *otcp = (struct tcphdr *)ol4;
                    osport = ntohs(otcp->source);
                    odport = ntohs(otcp->dest);
                }
                if (osport != sport || odport != dport) continue;
            }

            // Match
            gettimeofday(&curr_time, NULL);
            double rtt = (curr_time.tv_sec - sent_time.tv_sec) * 1000.0 + (curr_time.tv_usec - sent_time.tv_usec) / 1000.0;
            hop->last = rtt;
            if (hop->rtt_count < 500) {
                hop->rtts[hop->rtt_count++] = rtt;
            } else {
                memmove(hop->rtts, hop->rtts + 1, 499 * sizeof(double));
                hop->rtts[499] = rtt;
            }
            hop->recv++;
            if (strcmp(hop->addr, "*") == 0) {
                inet_ntop(AF_INET, &from.sin_addr, hop->addr, INET_ADDRSTRLEN);
            }
            if (ttl > max_reached_hop) max_reached_hop = ttl;
            if (icmp->type == ICMP_DEST_UNREACH && from.sin_addr.s_addr == dst.s_addr) {
                target_hop = ttl;
            }
            break;
        }
        if (l4_sock != -1 && FD_ISSET(l4_sock, &fds)) {
            ssize_t len = recvfrom(l4_sock, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
            if (len < sizeof(struct iphdr) + l4_hdr_len) continue;
            struct iphdr *rip = (struct iphdr *)buf;
            void *rl4 = (void *)(buf + rip->ihl * 4);
            uint16_t rsport, rdport;
            if (strcmp(protocol, "udp") == 0) {
                struct udphdr *rudp = (struct udphdr *)rl4;
                rsport = ntohs(rudp->source);
                rdport = ntohs(rudp->dest);
            } else {
                struct tcphdr *rtcp = (struct tcphdr *)rl4;
                rsport = ntohs(rtcp->source);
                rdport = ntohs(rtcp->dest);
            }
            if (rip->saddr != dst.s_addr || rsport != dport || rdport != sport) continue;

            // Match
            gettimeofday(&curr_time, NULL);
            double rtt = (curr_time.tv_sec - sent_time.tv_sec) * 1000.0 + (curr_time.tv_usec - sent_time.tv_usec) / 1000.0;
            hop->last = rtt;
            if (hop->rtt_count < 500) {
                hop->rtts[hop->rtt_count++] = rtt;
            } else {
                memmove(hop->rtts, hop->rtts + 1, 499 * sizeof(double));
                hop->rtts[499] = rtt;
            }
            hop->recv++;
            if (strcmp(hop->addr, "*") == 0) {
                inet_ntop(AF_INET, &from.sin_addr, hop->addr, INET_ADDRSTRLEN);
            }
            if (ttl > max_reached_hop) max_reached_hop = ttl;
            target_hop = ttl;
            break;
        }
    }
}

int main(int argc, char **argv) {
    // Parse arguments
    static struct option long_opts[] = {
        {"destination", required_argument, NULL, 'd'},
        {"protocol", required_argument, NULL, 'p'},
        {"port", required_argument, NULL, 'o'},
        {"payload-type", required_argument, NULL, 't'},
        {"payload", required_argument, NULL, 'l'},
        {"interval", required_argument, NULL, 'i'},
        {"max-hops", required_argument, NULL, 'm'},
        {NULL, 0, NULL, 0}
    };
    int opt;
    char *destination = NULL;
    while ((opt = getopt_long(argc, argv, "", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'd': destination = optarg; break;
            case 'p': protocol = optarg; break;
            case 'o': dport = atoi(optarg); break;
            case 't': payload_type = optarg; break;
            case 'l': payload_str = optarg; break;
            case 'i': interval = atof(optarg); break;
            case 'm': max_hops = atoi(optarg); break;
            default: fprintf(stderr, "Usage: sudo %s --destination <ip> --protocol <ip|udp|tcp> [--port <num>] --payload-type <text|hex> --payload <data> [--interval <sec>] [--max-hops <num>]\n", argv[0]); exit(1);
        }
    }
    if (!destination || !protocol || !payload_type || !payload_str) {
        fprintf(stderr, "Missing required arguments\n");
        fprintf(stderr, "Usage: sudo %s --destination <ip> --protocol <ip|udp|tcp> [--port <num>] --payload-type <text|hex> --payload <data> [--interval <sec>] [--max-hops <num>]\n", argv[0]);
        exit(1);
    }
    if (strcmp(protocol, "ip") != 0 && strcmp(protocol, "udp") != 0 && strcmp(protocol, "tcp") != 0) {
        fprintf(stderr, "Invalid protocol: ip, udp, or tcp\n");
        exit(1);
    }
    if ((strcmp(protocol, "udp") == 0 || strcmp(protocol, "tcp") == 0) && (dport < 0 || dport > 65535)) {
        fprintf(stderr, "Port required for udp or tcp\n");
        exit(1);
    }
    if (strcmp(protocol, "ip") == 0 && dport != -1) {
        fprintf(stderr, "No port for ip protocol\n");
        exit(1);
    }
    if (strcmp(payload_type, "text") != 0 && strcmp(payload_type, "hex") != 0) {
        fprintf(stderr, "Invalid payload-type: text or hex\n");
        exit(1);
    }

    if (strcmp(protocol, "udp") == 0 && dport == 53 && strcmp(payload_type, "text") == 0) {
        is_dns = 1;
        payload_bytes = NULL;
        payload_len = 0;
    } else {
        if (strcmp(payload_type, "text") == 0) {
            payload_len = strlen(payload_str);
            payload_bytes = malloc(payload_len);
            if (!payload_bytes) {
                fprintf(stderr, "Memory allocation failed\n");
                exit(1);
            }
            memcpy(payload_bytes, payload_str, payload_len);
        } else {  // hex
            size_t slen = strlen(payload_str);
            if (slen % 2 != 0) {
                fprintf(stderr, "Hex payload must have even length\n");
                exit(1);
            }
            payload_len = slen / 2;
            payload_bytes = malloc(payload_len);
            if (!payload_bytes) {
                fprintf(stderr, "Memory allocation failed\n");
                exit(1);
            }
            for (size_t i = 0; i < payload_len; i++) {
                char hex[3] = {payload_str[2 * i], payload_str[2 * i + 1], 0};
                payload_bytes[i] = (char)strtol(hex, NULL, 16);
            }
        }
    }

    dst_ip_str = destination;
    if (inet_pton(AF_INET, dst_ip_str, &dst_ip) != 1) {
        fprintf(stderr, "Invalid IP address\n");
        exit(1);
    }

    // Get local IP
    if (get_local_ip(my_ip_str) < 0) {
        strcpy(my_ip_str, "?.?.?.?");
    }
    inet_pton(AF_INET, my_ip_str, &my_ip);

    // Sockets
    send_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (send_sock < 0) {
        perror("socket (send)");
        fprintf(stderr, "Note: This program requires sudo for raw sockets.\n");
        exit(1);
    }
    icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (icmp_sock < 0) {
        perror("socket (icmp)");
        exit(1);
    }
    if (strcmp(protocol, "udp") == 0) {
        l4_sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        l4_proto = IPPROTO_UDP;
    } else if (strcmp(protocol, "tcp") == 0) {
        l4_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        l4_proto = IPPROTO_TCP;
    } else {
        l4_proto = PROTO_EXP;
    }
    if (l4_sock < 0 && strcmp(protocol, "ip") != 0) {
        perror("socket (l4)");
        exit(1);
    }

    // Seed random
    srand(time(NULL));

    // Signal
    signal(SIGINT, sigint_handler);

    // Init hops
    hops = malloc((max_hops + 1) * sizeof(struct hop));
    memset(hops, 0, (max_hops + 1) * sizeof(struct hop));
    for (int i = 0; i <= max_hops; i++) {
        strcpy(hops[i].addr, "*");
    }
    target_hop = max_hops;

    // Curses
    initscr();
    noecho();
    curs_set(0);
    nodelay(stdscr, TRUE);

    int ttl = 1;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    double next_send = tv.tv_sec + tv.tv_usec / 1000000.0;

    while (!stop_running) {
        gettimeofday(&tv, NULL);
        double now = tv.tv_sec + tv.tv_usec / 1000000.0;

        if (now >= next_send) {
            send_probe(ttl, dst_ip);
            next_send = now + interval;
            ttl = (ttl >= target_hop) ? 1 : ttl + 1;
        }

        // UI
        clear();
        int h, w;
        getmaxyx(stdscr, h, w);
        (void)w; // Suppress unused warning
        char title[256];
        if (is_dns) {
            snprintf(title, sizeof(title), "Live DNS Traceroute -> %s (%s) from %s", dst_ip_str, payload_str, my_ip_str);
        } else if (dport != -1) {
            snprintf(title, sizeof(title), "Live Traceroute -> %s protocol %s port %d from %s", dst_ip_str, protocol, dport, my_ip_str);
        } else {
            snprintf(title, sizeof(title), "Live Traceroute -> %s protocol %s from %s", dst_ip_str, protocol, my_ip_str);
        }
        mvaddstr(0, 0, title);
        attron(A_BOLD);
        mvaddstr(2, 0, "Hop Loss%   Pkts    Last     Avg    Best   Worst  StDev  Host");
        attroff(A_BOLD);

        int visible_hops = (h - 4 < max_reached_hop + 2) ? h - 4 : max_reached_hop + 2;
        for (int i = 1; i <= visible_hops; i++) {
            struct hop *hop = &hops[i];
            if (hop->sent == 0 && i > max_reached_hop) continue;
            char line[256];
            if (hop->sent == 0) {
                snprintf(line, sizeof(line), "%2d   ---     ---      *       *      *      *      *   %s", i, hop->addr);
            } else {
                double loss = 100.0 * (hop->sent - hop->recv) / hop->sent;
                char last_s[8], avg_s[8], best_s[7], worst_s[7], sdev_s[7];
                if (hop->rtt_count == 0) {
                    strcpy(last_s, "*     ");
                    strcpy(avg_s, "*     ");
                    strcpy(best_s, "*    ");
                    strcpy(worst_s, "*     ");
                    strcpy(sdev_s, "*    ");
                } else {
                    double sum = 0, sumsq = 0;
                    double min_rtt = hop->rtts[0];
                    double max_rtt = hop->rtts[0];
                    for (int j = 0; j < hop->rtt_count; j++) {
                        double r = hop->rtts[j];
                        sum += r;
                        sumsq += r * r;
                        if (r < min_rtt) min_rtt = r;
                        if (r > max_rtt) max_rtt = r;
                    }
                    double avg = sum / hop->rtt_count;
                    double variance = (hop->rtt_count > 1) ? (sumsq - (sum * sum / hop->rtt_count)) / (hop->rtt_count - 1) : 0.0;
                    double sdev = sqrt(variance);
                    snprintf(last_s, sizeof(last_s), "%6.2f", hop->last);
                    snprintf(avg_s, sizeof(avg_s), "%6.2f", avg);
                    snprintf(best_s, sizeof(best_s), "%5.2f", min_rtt);
                    snprintf(worst_s, sizeof(worst_s), "%5.2f", max_rtt);
                    snprintf(sdev_s, sizeof(sdev_s), "%5.2f", sdev);
                }
                snprintf(line, sizeof(line), "%2d %5.1f%%  %4d  %s  %s  %s  %s  %s  %s",
                         i, loss, hop->sent, last_s, avg_s, best_s, worst_s, sdev_s, hop->addr);
            }
            mvaddstr(i + 2, 0, line);
        }

        attron(A_REVERSE);
        mvaddstr(h - 1, 0, "Press q or Ctrl+C to quit");
        attroff(A_REVERSE);
        refresh();

        int ch = getch();
        if (ch == 'q' || ch == 'Q') stop_running = 1;

        usleep(10000);
    }

    nodelay(stdscr, FALSE);
    int h, w;
    getmaxyx(stdscr, h, w);
    (void)w; // Suppress unused warning
    attron(A_REVERSE);
    mvaddstr(h - 1, 0, "Finished -> press any key to exit...");
    attroff(A_REVERSE);
    refresh();
    getch();

    endwin();
    free(hops);
    if (payload_bytes) free(payload_bytes);
    close(send_sock);
    close(icmp_sock);
    if (l4_sock != -1) close(l4_sock);

    return 0;
}
