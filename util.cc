#include "util.h"

int32_t gmt2local(time_t t)
{
    int dt, dir;
    struct tm *gmt, *loc;
    struct tm sgmt;

    if (t == 0)
        t = time(NULL);
    gmt = &sgmt;
    *gmt = *gmtime(&t);
    loc = localtime(&t);
    dt = (loc->tm_hour - gmt->tm_hour) * 60 * 60 +
	    (loc->tm_min - gmt->tm_min) * 60;

    dir = loc->tm_year - gmt->tm_year;
    if (dir == 0)
        dir = loc->tm_yday - gmt->tm_yday;
    dt += dir * 24 * 60 * 60;

    return (dt);
}

char * ts_format(int sec, int usec)
{
    static char buf[sizeof("00:00:00.000000")];
    (void)snprintf(buf, sizeof(buf), "%02d:%02d:%02d.%06u",
                   sec / 3600, (sec % 3600) / 60, sec % 60, usec);

    return buf;
}

void ts_print(const struct timeval *tvp)
{
    int s;
    struct tm *tm;
    time_t Time;
    int32_t thiszone = gmt2local(0);
    s = (tvp->tv_sec + thiszone) % 86400;
    Time = (tvp->tv_sec + thiszone) - s;
    tm = gmtime (&Time);
    if (!tm)
        printf("Date fail  ");
    else
        printf("%04d-%02d-%02d %s ",
               tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday,
               ts_format(s, tvp->tv_usec));
}

 
void print_hex_ascii_line(const u_char *payload, int len, int offset)
{
    int i;
    int gap;
    const u_char *ch;
    ch = payload;
    for(i = 0; i < len; i++) {
        printf("%02X ", *ch);
        ch++;
    }
    if (len < 8) {
        printf(" ");
    }
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
            printf("   ");
        }
    }
    printf("   ");

    ch = payload;
    for(i = 0; i < len; i++) {
        if (isprint(*ch))
            printf("%c", *ch);
        else
            printf(".");
        ch++;
    }
    printf("\n");
    return;
}

/*
 * Function to open and return a raw socket on the injection interface.
 * Returns a socket file descriptor on success or NULL on failure.
 */
int create_injection_socket(char *interface){
    int inject_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(inject_sock < 0){
        perror("socket");
        return -1;
    }

    struct ifreq ifr;

    bzero(&ifr, sizeof(ifr));
    // use <interface>ap to bind to, this is created by executing
    // "iwpriv <interface> hostapd 1"

    // TODO:Modified here
    snprintf((char*)&ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);
    if(ioctl(inject_sock, SIOCGIFINDEX, &ifr) != 0) {
        perror("ioctl(SIOCGIFINDEX)");
        return -1;
    }

    struct sockaddr_ll addr;

    bzero(&addr, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = ifr.ifr_ifindex;

    if(bind(inject_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0){
        perror("bind");
        return -1;
    }

    bzero(&ifr, sizeof(ifr));
    snprintf((char*)&ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);

    // test to make sure the interface is the right type..
    if(ioctl(inject_sock, SIOCGIFHWADDR, &ifr) != 0) {
        perror("ioctl(SIOCGIFHWADDR)");
        return -1;
    }

    if(ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
        printf("Invalid family %04x\n", ifr.ifr_hwaddr.sa_family);
        return -1;
    }
    DEBUG_LOG("Create injection socket success, %d", inject_sock);
    return inject_sock;
}
