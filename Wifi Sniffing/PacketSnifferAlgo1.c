#include <pcap.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>	/* for clock_gettime */
//#include <sstream.h>
#define atoa(x)
//#define TIME_LT 5
//#define BILLION 1000000000L
/*prism value */
struct prism_value{
u_int32_t did;
u_int16_t status;
u_int16_t len;
u_int32_t data;
};

#define eps 2.22045e-016

/*prism header for traditional wireless card*/
struct prism_header{
	u_int32_t msgcode;
	u_int32_t msglen;
	struct prism_value hosttime;
	struct prism_value mactime;
	struct prism_value channel;
	struct prism_value rssi;
	struct prism_value sq;
	struct prism_value signal;
	struct prism_value noise;
	struct prism_value rate;
	struct prism_value istx;
	struct prism_value frmlen;
};
struct timespec start, end;
int flag=1;
int channel=-1;
double tm[12], count[12], tm1[12];
void handlePacket(const u_char* packet,const struct pcap_pkthdr* hdr, int len) {
	int i;
	
	struct prism_header* rth1 = (struct prism_header*)(packet);
	i = rth1->msglen;		// this is radiotap header which is added before the actual frame
	
	int j = i;
	printf("For this packet the mac addresses are \n");
    
    	// calculate the tmstamp
//    	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);		/* mark the end time */
//	printf("hjkkjhg\n");	
/*	long long int tl = tm[channel-1];
	tl*=BILLION;
	long long int tme =BILLION * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
	
	if(tme<tl){
		long double stp= (long double)tme/BILLION;
		printf("The timestamp is %Lf \n", stp);
	}
	else{	
		flag=0;
	}
	*/
	u_char *ptr; 
	struct ether_header *eptr;
	// print the mac address
	printf("Grabbed packet of length %d\n",hdr->len);
	    //printf("Recieved at ..... %s\n",ctime((const time_t*)&hdr.ts.tv_sec)); 
	    printf("Ethernet address length is %d\n",ETHER_HDR_LEN);

	    /* lets start with the ether header... */
	    eptr = (struct ether_header *) packet;

	    /* Do a couple of checks to see what packet type we have..*/
	    if (ntohs (eptr->ether_type) == ETHERTYPE_IP)
	    {
		printf("Ethernet type hex:%x dec:%d is an IP packet\n",
			ntohs(eptr->ether_type),
			ntohs(eptr->ether_type));
	    }else  if (ntohs (eptr->ether_type) == ETHERTYPE_ARP)
	    {
		printf("Ethernet type hex:%x dec:%d is an ARP packet\n",
			ntohs(eptr->ether_type),
			ntohs(eptr->ether_type));
	    }else {
		printf("Ethernet type %x not IP", ntohs(eptr->ether_type));
		//exit(1);
	    }

	    /* copied from Steven's UNP */
	    ptr = eptr->ether_dhost;
	    i = ETHER_ADDR_LEN;
	    printf(" Destination Address:  ");
	    do{
		printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
	    }while(--i>0);
	    printf("\n");

	    ptr = eptr->ether_shost;
	    i = ETHER_ADDR_LEN;
	    printf(" Source Address:  ");
	    do{
		printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
	    }while(--i>0);
	    printf("\n");

    
}

/* callback function that is passed to pcap_loop(..) and called each time 
 * a packet is recieved                                                    */
void my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
    handlePacket(packet, pkthdr, pkthdr->len);
}

int main(int argc , char ** argv){
	int i=1;
	// initialise timer for all channels;
	
	for(i=0; i<12; i++){
		tm[i]=3.0;
		tm1[i]=5.0;
		count[i]=0;
	} 
	
	// iterate for all the channels
	while(1){
		
		for(i=1; i<=12; i++){
			// mark the channel global var
			channel=i;
			printf("jhcbhjebcjkdbkjckjdvbjhdc jhvbhdfcvjbjhbvjhb jjhbjhbjcbxbjhvbjxcbvxb %d\n",channel );
			
			// set the channel 
			char cmd[27];
			sprintf (cmd, "sudo iwconfig wlan1 chan %d",i);
	
			//stringstream ss ="sudo iwconfig wlan0 chan ";
			//ss<<i;
			//string s = ss.str();
			
			system(cmd);
			printf(" in Channel num : %d\n",i);
			
			// start a timer of x seconds
			clock_gettime(CLOCK_REALTIME, &start);	/* mark start time */
			int ct =0;
			flag=1;
			
			while(flag==1){
				
				// do the stuff
				//printf("in while  1\n");
				char *dev; 
				char errbuf[PCAP_ERRBUF_SIZE];
				pcap_t* descr;
				const u_char *packet;
				struct pcap_pkthdr *hdr;     /* pcap.h */
				struct ether_header *eptr;  /* net/ethernet.h */

				//if(argc != 3){ fprintf(stdout,"Usage: %s interface_name numpackets\n",argv[0]);return 0;}

				//dev = argv[1]; 
				//dev = "ra0";
				dev = pcap_lookupdev(errbuf);
				//printf("after lookup  1\n");
				if(dev == NULL)
				{ printf("%s\n",errbuf); exit(1); }
				/* open device for reading */
				//printf("hello , after lookupdev\n");
				descr = pcap_open_live(dev,BUFSIZ,1,-1,errbuf);
				printf("datalink: %d\n",pcap_datalink(descr));
				
				pcap_loop(descr,1,my_callback,NULL);
				//printf("after pcap_loop\n");
				
				
							
				
				clock_gettime(CLOCK_REALTIME, &end);		/* mark the end time */
				//printf("hjkkjhg\n");	
				double tl = tm[channel-1];
				double tme = (end.tv_sec - start.tv_sec) ;
				
				
				if(tl-tme > eps){
					//long double stp= (long double)tme/BILLION;
					long double stp= (long double)tme;
					printf("The timestamp is %Lf \n", stp);
				}
				else{	
					flag=0;
				}
				ct++;
			}
			count[i-1]+=ct;
			
			printf("Total packets captured from channel %d in this phase %d\n", i, (int)count[i-1]);		
									
									
		}
		// after iterating all channels, decide their time for the next execution
		int total_packets=0;
		int j=0;
		for(j=0; j<12; j++){
			total_packets+=count[j];	
		}
		printf("Overall Total packets captured from all channels in this phase %d\n", total_packets);
		
			
		for(j=0; j<12; j++){
			tm[j]=(tm1[j]*count[j])/total_packets;
			printf("---------------------- time j : %f", tm[j]);	
		}
		
		for(j=0; j<12; j++){

			printf("---------------------- count j : %d\n",(int)count[j]);	
		}
				
	}	
	return 0;
}
