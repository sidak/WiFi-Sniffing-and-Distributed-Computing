#include "packetspammer.h"
#include "radiotap.h"
#include <time.h>
#include <unistd.h>
const u_int8_t MATH_TYPE_REQUEST     = 1; // Request for an expression to be solved
const u_int8_t MATH_TYPE_SEND_ANSWER = 4; // Send answer


struct MathPacketHeader {
	

	u_int32_t magic_number; 
	u_int8_t type_of_packet; // MATH_TYPE_*
	u_int16_t number_of_operands;
	int mathHeaderSize; 
};

const u_int8_t
	MATH_OPERATOR_PLUS        = 1,
	MATH_OPERATOR_MINUS       = 2,
	MATH_OPERATOR_MULTIPLY    = 3,
	MATH_OPERATOR_DIVIDE      = 4,
	MATH_OPERATOR_MODULO      = 5,
	MATH_OPERATOR_BITWISE_AND = 6,
	MATH_OPERATOR_BITWISE_OR  = 7,
	MATH_OPERATOR_BITWISE_XOR = 8;


/* wifi bitrate to use in 500kHz units */
// bit number 2
static const u8 u8aRatesToUse[] = {
    54*2,
    48*2,
    36*2,
    24*2,
    18*2,
    12*2,
    9*2,
    11*2,
    11, // 5.5 MHz
    2*2,
    1*2
};

/* this is the template radiotap header we send packets out with */

// little endian byte order for all data (including it_len, it_present)
/*
struct ieee80211_radiotap_header {
        u_int8_t        it_version;     // set to 0
        u_int8_t        it_pad;
        u_int16_t       it_len;         // entire length
        u_int32_t       it_present;     // fields present
} __attribute__((__packed__));
*/

// We need to change only rate if we want in this header
// http://www.radiotap.org/defined-fields
static const u8 u8aRadiotapHeader[] = {
    0x00, 0x00, // <-- radiotap version & padding (always 0)
    0x19, 0x00, // <-- entire length (radiotap header + data)
    0x6f, 0x08, 0x00, 0x00, // <-- bitmap for present fields
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // <-- timestamp (TSFT, 8 bytes)
    0x00, // <-- flags (Offset +0x10)
    0x6c, // <-- rate (0ffset +0x11)

    // Channel frequency (16 bits), Flags (16 bits)
    0x71, 0x09, 0xc0, 0x00, // <-- channel 2, 2417 MHz

    0xde, // <-- antenna signal (signed), RF signal power at the antenna in dBm (bit number 5)
    0x00, // <-- antenna noise power (,,,) bit number 6
    0x01, // <-- antenna, Unitless indication of the Rx/Tx antenna for this packet.
    // The first antenna is antenna 0. (bit number 11)
};

#define	OFFSET_FLAGS 0x10
#define	OFFSET_RATE 0x11

/* Penumbra IEEE80211 header */
// http://www.wildpackets.com/resources/compendium/wireless_lan/wlan_packets
static u8 u8aIeeeHeader[] = {
    0x08, 0x01, 0x00, 0x00,             // Frame control + duration
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Address 1 (broadcast)
    0x13, 0x22, 0x33, 0x44, 0x55, 0x66, // Address 2
    0x13, 0x22, 0x33, 0x44, 0x55, 0x66, // Address 3
    0x10, 0x86,                         // Sequence control
};

void printIeeeHeader() {
    int i=0;
    printf("IEEE header: ");
    for(; i<sizeof(u8aIeeeHeader); i++) {
        printf("%02X", u8aIeeeHeader[i]);
    }
    printf("\n");
}

// this is where we store a summary of the
// information from the radiotap header
typedef struct  {
    int m_nChannel;
    int m_nChannelFlags;
    int m_nRate;
    int m_nAntenna;
    int m_nRadiotapFlags;
} __attribute__((packed)) PENUMBRA_RADIOTAP_DATA;

unsigned int currentMacAddress = 1;

void changeMacAddress() {
    int addr2_offset = 12;      // We will change only last 4 bytes of mac address

    // change addr2
    unsigned char* ptr = u8aIeeeHeader + addr2_offset;
    *((unsigned int*) ptr) = currentMacAddress;

    ptr += 6;   // for addr3
    *((unsigned int*) ptr) = currentMacAddress;

    currentMacAddress++;
}

int flagHelp = 0, flagMarkWithFCS = 0;
int NUM=100;
int num=0;
void Dump(u8 * pu8, int nLength)
{
    char sz[256], szBuf[512], szChar[17], *buf, fFirst = 1;
    unsigned char baaLast[2][16];
    uint n, nPos = 0, nStart = 0, nLine = 0, nSameCount = 0;

    buf = szBuf;
    szChar[0] = '\0';

    for (n = 0; n < nLength; n++) {
        baaLast[(nLine&1)^1][n&0xf] = pu8[n];
        if ((pu8[n] < 32) || (pu8[n] >= 0x7f))
            szChar[n&0xf] = '.';
        else
            szChar[n&0xf] = pu8[n];
        szChar[(n&0xf)+1] = '\0';
        nPos += sprintf(&sz[nPos], "%02X ",
                        baaLast[(nLine&1)^1][n&0xf]);
        if ((n&15) != 15)
            continue;
        if ((memcmp(baaLast[0], baaLast[1], 16) == 0) && (!fFirst)) {
            nSameCount++;
        } else {
            if (nSameCount)
                buf += sprintf(buf, "(repeated %d times)\n",
                               nSameCount);
            buf += sprintf(buf, "%04x: %s %s\n",
                           nStart, sz, szChar);
            nSameCount = 0;
            printf("%s", szBuf);
            buf = szBuf;
        }
        nPos = 0; nStart = n+1; nLine++;
        fFirst = 0; sz[0] = '\0'; szChar[0] = '\0';
    }
    if (nSameCount)
        buf += sprintf(buf, "(repeated %d times)\n", nSameCount);

    buf += sprintf(buf, "%04x: %s", nStart, sz);
    if (n & 0xf) {
        *buf++ = ' ';
        while (n & 0xf) {
            buf += sprintf(buf, "   ");
            n++;
        }
    }
    buf += sprintf(buf, "%s\n", szChar);
    printf("%s", szBuf);
}

void usage(void)
{
    printf(
                "(c)2006-2007 Andy Green <andy@warmcat.com>  Licensed under GPL2\n"
                "\n"
                "Usage: packetspammer [options] <interface>\n\nOptions\n"
                "-d/--delay <delay> Delay between packets\n\n"
                "-f/--fcs           Mark as having FCS (CRC) already\n"
                "                   (pkt ends with 4 x sacrificial - chars)\n"
                "Example:\n"
                "  echo -n mon0 > /sys/class/ieee80211/phy0/add_iface\n"
                "  iwconfig mon0 mode monitor\n"
                "  ifconfig mon0 up\n"
                "  packetspammer mon0        Spam down mon0 with\n"
                "                            radiotap header first\n"
                "\n");
    exit(1);
}


int main(int argc, char *argv[])
{
    // nOrdinal is packet number e.g. 1,2,3...
    int nOrdinal = 0;
    num=0;
    // send 10 packets/second
    int nDelay = 100000;     // time in microseconds

    int nRateIndex = 0, bytes;
    pcap_t *ppcap = NULL;
    struct bpf_program bpfprogram;
    char * szProgram = "";

    // *************** READ COMMAND LINE ARGUMENTS *****************
    while (1) {
        int nOptionIndex;
        static const struct option optiona[] = {
            { "delay", required_argument, NULL, 'd' },
            { "fcs", no_argument, &flagMarkWithFCS, 1 },
            { "help", no_argument, &flagHelp, 1 },
            { 0, 0, 0, 0 }
        };
        int c = getopt_long(argc, argv, "d:hf", optiona, &nOptionIndex);

        // no more option character
        if (c == -1)
            break;      // exit while loop

        switch (c)
        {
        case 0: // long option
            break;

        case 'h': // help
            usage();

        case 'd': // delay
            nDelay = atoi(optarg);
            break;

        case 'f': // mark as FCS attached
            flagMarkWithFCS = 1;
            break;

        default:
            printf("unknown switch %c\n", c);
            usage();
            break;
        }
    }

    if (optind >= argc)
        usage();


    // open the interface in pcap
    // obtain a packet capture handle to look at packets on the network
    char* interface_name = argv[optind];	// device
    int snapshot_length = 800;
    int promiscuous = 1;	// set the device into promiscuous mode
    int timeout_ms = 20;	// timeout in milliseconds
    char szErrbuf[PCAP_ERRBUF_SIZE];
    szErrbuf[0] = '\0';
    ppcap = pcap_open_live(interface_name, snapshot_length, promiscuous, timeout_ms, szErrbuf);
    if (ppcap == NULL) {
        printf("Unable to open interface %s in pcap: %s\n", interface_name, szErrbuf);
        return (1);
    }

    // returns the link-layer header type for the live capture
    int linkHeaderType = pcap_datalink(ppcap);
    int nCaptureHeaderLength = 0, n80211HeaderLength = 0;

    switch (linkHeaderType) {

    case DLT_PRISM_HEADER:
        printf("DLT_PRISM_HEADER Encap\n");
        nCaptureHeaderLength = 0x40;
        n80211HeaderLength = 0x20; // ieee80211 comes after this
        szProgram = "radio[0x4a:4]==0x13223344";
        break;

    case DLT_IEEE802_11_RADIO:
        printf("DLT_IEEE802_11_RADIO Encap\n");
        nCaptureHeaderLength = 0x40;
        n80211HeaderLength = 0x18; // ieee80211 comes after this
        szProgram = "ether[0x0a:4]==0x13223344";
        break;

    default:
        printf("!!! unknown encapsulation on %s !\n", argv[1]);
        return (1);
    }

    // Listen for any address like 13:22:33:44:xx:xx
    if (pcap_compile(ppcap, &bpfprogram, szProgram, 1, 0) == -1) {
        puts(szProgram);
        puts(pcap_geterr(ppcap));
        return (1);
    } else {
        if (pcap_setfilter(ppcap, &bpfprogram) == -1) {
            puts(szProgram);
            puts(pcap_geterr(ppcap));
        } else {
            printf("RX Filter applied\n");
        }
        pcap_freecode(&bpfprogram);
    }

    // return 0 immediately rather than blocking waiting for packets to arrive
    pcap_setnonblock(ppcap, 1, szErrbuf);

    printf("(delay between packets %dus)\n", nDelay);

    u8 u8aSendBuffer[500];
    memset(u8aSendBuffer, 0, sizeof (u8aSendBuffer));

    char fBrokenSocket = 0;
	printf("------------------------- SENDING PACKETS -----------------------\n\n\n"); 
    while (!fBrokenSocket) {
        u8 * pu8 = u8aSendBuffer;
        struct pcap_pkthdr * ppcapPacketHeader = NULL;
        struct ieee80211_radiotap_iterator rti;
        PENUMBRA_RADIOTAP_DATA prd;

        // ******************** RECEIVE *************************

        // reads the next packet and returns a success/failure indication
        u8 * pu8Payload = u8aSendBuffer;
        int retval = pcap_next_ex(ppcap, &ppcapPacketHeader, (const u_char**)&pu8Payload);

/*
 * retval:
 * 1 if the packet was read without problems,
 * 0 if packets are being read from a live capture, and the timeout expired,
 * -1 if an error occurred while reading the packet, and
 * -2 if packets are being read from a ``savefile'', and there are no more packets to read  from  the  save‐file.
 */
        // if failure, exit the while loop
        if (retval < 0) {
            fBrokenSocket = 1;
            continue;
        }

        // if timeout expired (retval == 0)
        if (retval != 1)
            goto do_tx;

        u16 u16HeaderLen = (pu8Payload[2] + (pu8Payload[3] << 8));

        printf("rtap: ");
        Dump(pu8Payload, u16HeaderLen);

        if (ppcapPacketHeader->len <
                (u16HeaderLen + n80211HeaderLength))
            continue;

        bytes = ppcapPacketHeader->len -
                (u16HeaderLen + n80211HeaderLength);
        if (bytes < 0)
            continue;

        if (ieee80211_radiotap_iterator_init(&rti,
                                             (struct ieee80211_radiotap_header *)pu8Payload,
                                             bytes) < 0)
            continue;

        int n;
        while ((n = ieee80211_radiotap_iterator_next(&rti)) == 0) {

            switch (rti.this_arg_index) {
            case IEEE80211_RADIOTAP_RATE:
                prd.m_nRate = (*rti.this_arg);
                break;

            case IEEE80211_RADIOTAP_CHANNEL:
                prd.m_nChannel =
                        le16_to_cpu(*((u16 *)rti.this_arg));
                prd.m_nChannelFlags =
                        le16_to_cpu(*((u16 *)(rti.this_arg + 2)));
                break;

            case IEEE80211_RADIOTAP_ANTENNA:
                prd.m_nAntenna = (*rti.this_arg) + 1;
                break;

            case IEEE80211_RADIOTAP_FLAGS:
                prd.m_nRadiotapFlags = *rti.this_arg;
                break;

            }
        }

        pu8Payload += u16HeaderLen + n80211HeaderLength;

        if (prd.m_nRadiotapFlags & IEEE80211_RADIOTAP_F_FCS)
            bytes -= 4;

        Dump(pu8Payload, bytes);
	
        // *********************** TRANSMIT ***********************
do_tx:
        
        // copy the radio tap header into send buffer
        memcpy(u8aSendBuffer, u8aRadiotapHeader, sizeof (u8aRadiotapHeader));
        if (flagMarkWithFCS)    // if frame includes FCS
            pu8[OFFSET_FLAGS] |= IEEE80211_RADIOTAP_F_FCS;

        // Use a different rate every time
        int nRate = pu8[OFFSET_RATE] = u8aRatesToUse[nRateIndex++];
        if (nRateIndex >= sizeof (u8aRatesToUse))
            nRateIndex = 0;
        pu8 += sizeof (u8aRadiotapHeader);

		
	struct MathPacketHeader mathPacketHeader;
	struct MathPacketHeader * mptr;
	mptr= &mathPacketHeader;
	mptr->magic_number=21212020;

	char req= *argv[3];
	
	if(req=='q'){
		mptr->type_of_packet=MATH_TYPE_REQUEST;	
	}
	else {
		mptr->type_of_packet=MATH_TYPE_SEND_ANSWER;
	}	
	mptr->number_of_operands=strlen(argv[2]); // ?
	mptr->mathHeaderSize=sizeof(mathPacketHeader);
	// copy the math header into send buffer
	memcpy(pu8, mptr, sizeof (mathPacketHeader));
        pu8 += sizeof (mathPacketHeader);


	printf("Packet with expression %s of type %c \n", argv[2],req );
	
				       	 
	

        // Payload
        pu8 += sprintf((char *)pu8, argv[2]);

        size_t packetSize = pu8 - u8aSendBuffer;
        int bytesWritten = pcap_inject(ppcap, u8aSendBuffer, packetSize);
        if (bytesWritten != (packetSize)) {
            perror("Trouble injecting packet");
            return (1);
        }
	if(req=='q'){
		num++;
		//printf("num  is %d\n",num);	
	}

        // wait for nDelay micro seconds before receiving/sending a packet again
        if (nDelay)
            usleep(nDelay);
	
	if(num>NUM) {  
		printf("------------------------- FINISHED SENDING -----------------------\n\n\n"); 
		printf("WAITIING FOR SERVER TO COMPUTE AND SEND PACKET\n");
		sleep(3);
		printf("CAPTURING THE COMPUTED PACKET FROM THE SERVER\n");
		char cmdbuf[300];
		sprintf(cmdbuf, "sudo ./packetreceiver %s %d", interface_name, 200);
		system(cmdbuf);
		exit(0);
	}
    }
	printf("------------------------- FINISHED SENDING -----------------------\n\n\n"); 
    return (0);
}
