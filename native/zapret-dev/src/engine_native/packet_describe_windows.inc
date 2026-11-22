/* MIT. Keep the legacy stdout calls for the display comparison. */
void print_ip(const struct ip *ip) { char text[66];str_ip(text,sizeof(text),ip);printf("%s",text); }
void print_ip6hdr(const struct ip6_hdr *ip,uint8_t protocol) { char text[132];str_ip6hdr(text,sizeof(text),ip,protocol);printf("%s",text); }
void print_tcphdr(const struct tcphdr *tcp) { char text[80];str_tcphdr(text,sizeof(text),tcp);printf("%s",text); }
void print_udphdr(const struct udphdr *udp) { char text[30];str_udphdr(text,sizeof(text),udp);printf("%s",text); }
void print_icmphdr(const struct icmp46 *icmp,bool ipv6) { char text[48];str_icmphdr(text,sizeof(text),ipv6,icmp);printf("%s",text); }
