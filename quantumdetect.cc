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

#include <map>
#include <string>

#include "log.h"
using namespace std;

extern char * optarg;
static const int ARG_LEN = 256;
static const int SIZE_ETHERNET = 14;
static const char * DEFAULT_INTERFACE = "eth0";
static const int MAX_PAYLOAD_SIZE = 70*1024; // max payload bytes per packet
static const int PACKET_NUM = 1024*10;
static std::map<uint64_t, string> payload_map;
typedef struct user_data_t
{
    char * interface;

} user_data;

static const char * http_filter = "tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354 or "
        "tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420";

void pcap_callback(u_char * user,
                   const struct pcap_pkthdr *h, const u_char *bytes);

static char * filename = NULL;
int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf ("Invalid argument!\n"
                "quantumdetect [-i interface] [-r file]  expression\n");
        return -1;
    }

    char interface[ARG_LEN];
    strncpy(interface, DEFAULT_INTERFACE, ARG_LEN);
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
            filename = optarg;
            printf ("[DEBUG] read from pcap file: %s\n", filename);
            break;

        default:
            DEBUG_LOG ("Invalid argument!\n"
                       "quantumdetect [-i interface] [-r file]  expression\n");
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


    char errbuf[512];
    struct bpf_program bpf;
    pcap_t * pf;


    if (filename != NULL) {
        pf = pcap_open_offline(filename, errbuf);
        if (NULL == pf) {
            fprintf(stderr, "Fail to pcap_open_offline: %m");
            return -1;
        }
        int dl = pcap_datalink(pf);
        const char * dl_name = pcap_datalink_val_to_name(dl);
        if (dl_name == NULL) {
            fprintf(stderr, "reading from file %s, link-type %u\n",
                    filename, dl);
        } else {
            fprintf(stderr,
                    "reading from file %s, link-type %s (%s)\n",
                    filename, dl_name,
                    pcap_datalink_val_to_description(dl));
        }
    } else {

        pf = pcap_open_live(interface, 0xffff, 1, 1, errbuf);
        if (pf == NULL) {
            printf("Error rerturned from pcap_open_live: %s\n", errbuf);
            return -1;
        }
    }

    if (pcap_compile(pf, &bpf, exp, 0, 0) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n",
                exp, pcap_geterr(pf));
    }
        
    if (pcap_setfilter(pf, &bpf) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n",
                exp, pcap_geterr(pf));
    }

    pcap_loop(pf, PACKET_NUM, pcap_callback, (u_char*)&udata);

    pcap_freecode(&bpf);
    pcap_close(pf);
    return 0;
}


void pcap_callback(u_char *user, const struct pcap_pkthdr *h, const u_char *packet)
{
    user_data * pdata = (user_data *)user;
    struct ethhdr * ehdr = (struct ethhdr *)packet;
    struct iphdr * ip = (struct iphdr*)(packet + SIZE_ETHERNET);
    int iphdr_len = ip->ihl * 4;

    if (ip->protocol != IPPROTO_TCP) {
        printf("[DEBUG] Other protocol we do not support yet\n");
        return;        
    }

    struct tcphdr * tcp = (struct tcphdr*)(packet + SIZE_ETHERNET + iphdr_len);
    int tcphdr_len = tcp->doff * 4;    /* TCP header size */
    if (tcphdr_len < 20) {
        printf("[DEBUG] Invalid TCP header length: %u bytes\n",
               tcphdr_len);
        return;
    }
    char * payload = (char *)(packet + SIZE_ETHERNET + iphdr_len + tcphdr_len);
    int size_payload = ntohs(ip->tot_len) - (iphdr_len + tcphdr_len);
    uint64_t seq = ntohl(tcp->seq);
    uint64_t key = (((uint64_t)ip->daddr << 32)) | seq;

    std::string value;
    //value = payload;
    if (size_payload == 0) {
        return;
    } else if (size_payload > MAX_PAYLOAD_SIZE) {
        DEBUG_LOG("The payload length %d is out of limitation %d",
                  size_payload, MAX_PAYLOAD_SIZE);
        return;
    }
    payload[size_payload] = '\0';

    // DEBUG_LOG("seq %u ack_seq %u", ntohl(tcp->seq), ntohl(tcp->ack_seq));
    // DEBUG_LOG("Payload %d bytes", size_payload);
    // DEBUG_LOG("payload %s", payload);

    std::pair<std::map<uint64_t,string>::iterator,bool> ret;
    ret = payload_map.insert(std::pair<uint64_t, string>(key, payload));
    if (ret.second == true) {
        // Inserting succeed
        //DEBUG_LOG("insert hashmap with key[%llu] successfully", key);
        return;
    }
    // Now the inserting failed because the key already exists
    //DEBUG_LOG("key %llu already exists", key);

    if (0 != strncmp(payload, ret.first->second.c_str(), size_payload)) {

        printf ("WARNING! You are under attack !!\n");
        printf ("The fake response is %s\n", ret.first->second.c_str());
        printf ("The true response is %s\n", payload);
    }

END_OF_CB:
    fflush(stdout);
}


