#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <math.h>

#define BLANK ' '
#define TAB '\t'
#define MAX 50

struct ieee80211_radiotap_header {
        u_int8_t        it_version;     /* set to 0 */
        u_int8_t        it_pad;
        u_int16_t       it_len;         /* entire length */
        u_int32_t       it_present;     /* fields present */
};

const u_int8_t MATH_TYPE_REQUEST     = 1; // Request for an expression to be solved
const u_int8_t MATH_TYPE_SEND_ANSWER = 4; // Send answer


struct MathPacketHeader {

	u_int32_t magic_number; // Must be set to 9770010
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


/*========defined but not used=========*/
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


// -------------------------Code for infix_to_postfix and then converting postfix to integer-------------------
u_char expr[300];
void push(long int symbol);
long int pop();
void infix_to_postfix();
int priority(char symbol);
int isEmpty();
int white_space(char);

char infix[MAX], postfix[MAX];
long int stack[MAX];
int top;
long int eval_post();
long int rpn(char arr[])
{
	top=-1;
	infix_to_postfix();
	return eval_post();
}

void infix_to_postfix()
{
	unsigned int i,p=0,xx=0;
	char next;
	char symbol;
	for(i=0;i<strlen(expr);i++)
	{
		symbol=expr[i];
		if(!white_space(symbol))
		{
			switch(symbol)
			{
				case '(':
					push(symbol);
					break;
				case ')':
					while((next=pop())!='(')
						postfix[p++] = next;
					break;
				case '+':
				case '-':
				case '*':
				case '/':
				case '%':
				case '^':
					postfix[p++] = '.';
					xx=  0;
					if(!isEmpty()){
						while( !isEmpty() &&  priority(stack[top])>= priority(symbol) ){
							postfix[p++] = pop();
						}
					}
					push(symbol);
					break;
				default: /*if an operand comes*/
					xx = 1;
					postfix[p++]=symbol;
			}
		}
	}
	if(xx==1){
		postfix[p++] = '.';
	}
	while(!isEmpty( ))
		postfix[p++]=pop();
	postfix[p]='\0'; /*End postfix with'\0' to make it a string*/
}

/*This function returns the priority of the operator*/
int priority(char symbol)
{
	switch(symbol)
	{
		case '(':
			return 0;
		case '+':
		case '-':
			return 1;
		case '*':
		case '/':
		case '%':
			return 2;
		case '^':
			return 3;
		default :
			return 0;
	}
}

void push(long int symbol)
{
	if(top>MAX)
	{
		printf("Stack overflow\n");
		exit(1);
	}
	stack[++top]=symbol;
}

long int pop()
{
	if( isEmpty() )
	{
		printf("Stack underflow\n");
		exit(1);
	}
	return (stack[top--]);
}
int isEmpty()
{
	if(top==-1)
		return 1;
	else
		return 0;
}

int white_space(char symbol)
{
	if( symbol == BLANK || symbol == TAB )
		return 1;
	else
		return 0;
}

long int eval_post()
{
	long int a,b,temp,result;
	unsigned int i = 0;
	while(i<strlen(postfix)){
		long int x = 0,temp = 0;
		while(postfix[i]!='.'){
			if(postfix[i]<='9' && postfix[i]>='0'){
				temp = temp*10 + (postfix[i]-'0');
				x++;
				i++;
			} else {
				break;
			}
		}
		if(x!=0){
			push(temp);
		} else {
			a=pop();
			b=pop();
			switch(postfix[i])
			{
				case '+':
					temp=b+a; break;
				case '-':
					temp=b-a;break;
				case '*':
					temp=b*a;break;
				case '/':
					temp=b/a;break;
				case '%':
					temp=b%a;break;
				case '^':
					temp=(long int )pow(b,a);
			}
			push(temp);
		}
		i++;
	}
	result=pop();
	return result;
}
// --------------------------------------------------------------------------------
int magic_number= 21212020;// ?

char *dev; 
void handlePacket(const u_char* packet, int len) {
	int i;
	int id, length, size, type;
	//printf("------------------------- IN SERVER -----------------------\n\n\n"); 
	struct ieee80211_radiotap_header* rth = (struct ieee80211_radiotap_header*)(packet);
	
	struct MathPacketHeader * mptr= (struct MathPacketHeader*)(packet+(rth->it_len));
	id=mptr->magic_number;
	length = mptr->number_of_operands;
	size = mptr->mathHeaderSize;
	type=mptr->type_of_packet; 
	// print the expression	
	int j ;		
	
	if(id==magic_number){ 
		printf("The received packet has the data ");
	 	i= rth->it_len+size; //?
		for(j=0; j<length; j++){
			expr[j]=packet[i];			
			printf("%c", packet[i]);
			i++;	
		}
		expr[length]='\0';
		printf("\n");

	}
	else {
		printf("Some other packet Captured\n");
		return;
	}

	if(type==MATH_TYPE_SEND_ANSWER){

		printf("\n\nPacket Captured \n Result Evaluated : %s \n\n",expr);		
	}
	else {

		long int ans = rpn(expr);
		char cmdbuf[300];
		printf("------------------------- TO CLIENT -----------------------\n\n\n"); 
		sprintf(cmdbuf, "sudo ./packetspammer %s %d %c", dev, ans, 'a');
		system(cmdbuf);
		exit(0);   
	}
	
	
}

/* callback function that is passed to pcap_loop(..) and called each time 
 * a packet is recieved                                                    */
void my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
    handlePacket(packet, pkthdr->len);
}

int main(int argc,char **argv)
{ 
    int i;
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    const u_char *packet;
    struct pcap_pkthdr hdr;     /* pcap.h */
    struct ether_header *eptr;  /* net/ethernet.h */

    if(argc != 3){ fprintf(stdout,"Usage: %s interface_name numpackets\n",argv[0]);return 0;}

    dev = argv[1];
    
    if(dev == NULL)
    { printf("%s\n",errbuf); exit(1); }
    /* open device for reading */

    descr = pcap_open_live(dev,BUFSIZ,1,-1,errbuf);
    printf("datalink: %d\n",pcap_datalink(descr));
	printf("------------------------- RECEIVING PACKETS -----------------------\n\n\n"); 
    pcap_loop(descr,atoi(argv[2]),my_callback,NULL);
			printf("------------------------- RECEIVING FINISHED -----------------------\n\n\n"); 	
    fprintf(stdout,"\nDone!\n");
    return 0;

    
    
}
