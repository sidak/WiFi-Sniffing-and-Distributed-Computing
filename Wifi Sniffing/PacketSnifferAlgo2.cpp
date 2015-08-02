#include <iostream>
#include <pthread.h>
#include <unistd.h>
#include <bits/stdc++.h>
#include <pcap.h>
#include <cstdio>
#include <cstdlib>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <math.h>

using namespace std;

#define atoa(x)

//used to compare double values
#define eps 2.22045e-016

/*prism value */
struct prism_value{
	u_int32_t did;
	u_int16_t status;
	u_int16_t len;
	u_int32_t data;
};

/*prism header for traditional wireless card*/
struct prism_header{
	u_int32_t msgcode;
	u_int32_t msglen;
	struct prism_value hosttime;
	struct prism_value machan_time;
	struct prism_value channel;
	struct prism_value rssi;
	struct prism_value sq;
	struct prism_value signal;
	struct prism_value noise;
	struct prism_value rate;
	struct prism_value istx;
	struct prism_value frmlen;
};

//----- global variables used --------//
char* device_name;
int packer_no = 1;
int flag=1;
int current_chan = 0;
double tm[12], counter[12], tm1[12];
int chan_time[12];
pcap_t* descr;

//---- clock variables--- //
clock_t start;
double duration;

map < string , int > per_min_stat;

//---- variables to store thread ids---//
pthread_t tid[2];
bool master_ready = true,slave_ready = false;

//---- function to handle packet data to find mac-id ---//
void handlePacket(const u_char* packet, const struct pcap_pkthdr* hdr, int len) {
    int i;
    
    struct prism_header* rth1 = (struct prism_header*)(packet);
    i = rth1->msglen;       // this is radiotap header which is added before the actual frame
    
    int j = i;
    //printf("For this packet the mac addresses are \n");
    
    u_char *ptr;
    struct ether_header *eptr;
    // print the mac address
    //printf("Grabbed packet of length %d\n",hdr->len);
    //printf("Recieved at ..... %s\n",chan_time((const time_t*)&hdr.ts.tv_sec));
    //printf("Ethernet address length is %d\n",ETHER_HDR_LEN);
    
    /* lets start with the ether header... */
    eptr = (struct ether_header *) packet;
    
    /* Do a couple of checks to see what packet type we have..*/
    if (ntohs (eptr->ether_type) == ETHERTYPE_IP) {
        printf("Ethernet type hex:%x dec:%d is an IP packet\n",
               ntohs(eptr->ether_type),
               ntohs(eptr->ether_type));
    } else if (ntohs (eptr->ether_type) == ETHERTYPE_ARP) {
        printf("Ethernet type hex:%x dec:%d is an ARP packet\n",
               ntohs(eptr->ether_type),
               ntohs(eptr->ether_type));
    } else {
        //printf("Ethernet type %x not IP", ntohs(eptr->ether_type));
        //exit(1);
    }
        
    duration = (clock() - start ) / (double) CLOCKS_PER_SEC;

    /* copied from Steven's UNP */
    ptr = eptr->ether_dhost;
    i = ETHER_ADDR_LEN;
    //printf(" Destination Address:  ");
    do{
        //printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
    }while(--i>0);
    cout<<packer_no<<"\t";
    packer_no++;
    ptr = eptr->ether_shost;
    i = ETHER_ADDR_LEN;
    //printf(" Source Address:  ");
    do{
        printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
    }while(--i>0);
    printf("\t %.6lf\n",duration);
}

/* callback function that is passed to pcap_loop(..) and called each time
 * a packet is recieved                                                    */
void my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char*
				 packet)
{
	handlePacket(packet, pkthdr, pkthdr->len);
	counter[current_chan] += (1.0);
}

void calculateStats(){
	// after iterating all channels, decide their time for the next execution
	int total_packets=0;
	int j=0;
	for(j=0; j<12; j++){
		total_packets+=counter[j];
	}
	printf("\n--------------- THE STATISTICS FOR THIS PHASE ARE: ---------------\n\n");
	printf("Overall Total packets captured from all channels in this phase %d\n", total_packets);
	
	
	printf("The new time-priorities are: \n");
	for(j=0; j<12; j++){
		chan_time[j]=(24*counter[j])/total_packets;
		printf("---------------------- CHANNEL %d : %d\n",j+1, chan_time[j]);
	}
	printf("\nThe count of total packets received till now from each channel are:\n");
	for(j=0; j<12; j++){
		printf("---------------------- CHANNEL %d : %d\n",j+1,(int)counter[j]);
	}
	
	printf("\nPer-Minute Statistics are as follows:\n");
	map < string,int > :: iterator it;
	for(it = per_min_stat.begin();it!=per_min_stat.end();it++){
		cout<<"---------------------- MAC-ID: "<<it->first<<" \t COUNT: "<<it->second<<"\n";
	}
	printf("\n");
}

void* my_func(void * arg){
	pthread_t myID = pthread_self();
	if(pthread_equal(myID,tid[0])){
		//it is the master thread
		
		//wait until the slave starts recieving packets
		while(!slave_ready);
		
		while(1){
			//set the channel
			//printf("sleeping\n");
			//printf("current_channel is %d\n", current_chan);
			char cmd[27];
			sprintf (cmd, "sudo iwconfig %s chan %d",device_name,current_chan+1);
			system(cmd);
			
			//make the master sleep
			sleep(floor(chan_time[current_chan]));
			
			//printf("woke up\n");
			
			printf("Total packets captured from channel %d in this phase %d\n", current_chan+1, (int)counter[current_chan]);
			
			current_chan++;
			
			if(current_chan==12){
				master_ready = false;
				slave_ready = false;
				calculateStats();
				current_chan = 0;
				master_ready = true;
				//return NULL;
			}
		}
	} else {
		//it is the slave thread
		while(!master_ready);
		slave_ready = true;
		printf("Capturing the packet\n");
		//capture the packets
		pcap_loop(descr,-1,my_callback,NULL);
	}
}

int main(int argc , char ** argv){
	start = std::clock();
	int i=1;
	
	//ready the device and change its mode to monitor mode
	device_name = argv[1];
	
	char cmd[27];
	sprintf (cmd, "sudo ifconfig %s down",device_name);
	system(cmd);
	sprintf (cmd, "sudo iwconfig %s mode monitor",device_name);
	system(cmd);
	sprintf (cmd, "sudo ifconfig %s up",device_name);
	system(cmd);
	
	// initialise timer for all channels;
	for(i=0; i<12; i++){
		counter[i] = 0;
		chan_time[i] = 1.0;
	}
	
	// initialise the device
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	const u_char *packet;
	struct pcap_pkthdr *hdr;     /* pcap.h */
	struct ether_header *eptr;  /* net/ethernet.h */
	
	//if(argc != 3){ fprintf(stdout,"Usage: %s interface_name numpackets\n",argv[0]);return 0;}
	
	//dev = argv[1];
	dev = "wlan1";
	//dev = pcap_lookupdev(errbuf);
	if(dev == NULL)
	{ printf("%s\n",errbuf); exit(1); }
	/* open device for reading */
	descr = pcap_open_live(dev,BUFSIZ,1,-1,errbuf);
	printf("datalink: %d\n",pcap_datalink(descr));
	
	// create the two threads - one master to control channels and one slave to capture packets
	for(int i=0;i<2;i++){
		int err = pthread_create(&(tid[i]),NULL,&my_func,NULL);
	}
	
	sleep(500);
	
	return 0;
}
