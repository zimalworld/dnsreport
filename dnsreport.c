
#include<stdio.h>	//printf
#include<string.h>	//strlen
#include<stdlib.h>	//malloc
#include<sys/socket.h>	//you know what this is for
#include<arpa/inet.h>	//inet_addr , inet_ntoa , ntohs etc
#include<netinet/in.h>
#include<unistd.h>	//getpid

#define MAXBUFZISE 65536

#define T_A 1 //Ipv4 address
#define T_AAAA 0x1c // ipv6  28 = 0x1C
#define T_NS 2 //Nameserver
#define T_CNAME 5 // canonical name
#define T_SOA 6 /* start of authority zone */
#define T_PTR 12 /* domain name pointer */
#define T_MX 15 //Mail server

void HostNameFormat(unsigned char* name);
void DnsNameFormat (unsigned char*,unsigned char*);
unsigned char* ReadName (unsigned char*,unsigned char*,int*);
void getHostByNameAndDNSServer(unsigned char *host,unsigned char* dns_server, int query_type);
int createDnsQueryBuffer(unsigned char* buf,int query_type,unsigned char *host);
void processDnsMsgBuffer(unsigned char* buf,int offset);

//DNS header structure
struct DNS_HEADER
{
	unsigned short id; // identification number

	unsigned char rd :1; // recursion desired
	unsigned char tc :1; // truncated message
	unsigned char aa :1; // authoritive answer
	unsigned char opcode :4; // purpose of message
	unsigned char qr :1; // query/response flag

	unsigned char rcode :4; // response code
	unsigned char cd :1; // checking disabled
	unsigned char ad :1; // authenticated data
	unsigned char z :1; // its z! reserved
	unsigned char ra :1; // recursion available

	unsigned short q_count; // number of question entries
	unsigned short ans_count; // number of answer entries
	unsigned short auth_count; // number of authority entries
	unsigned short add_count; // number of resource entries
};

//Constant sized fields of query structure
struct QUESTION
{
	unsigned short qtype;
	unsigned short qclass;
};

//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct R_DATA
{
	unsigned short type;
	unsigned short _class;
	unsigned int ttl;
	unsigned short data_len;

};

struct R_DATA_V6
{
	unsigned short type;
	unsigned short _class;
	unsigned int ttl;
	unsigned short data_len;
	unsigned short uknown;

};
#pragma pack(pop)

//Pointers to resource record contents
struct RES_RECORD
{
	unsigned char *name;
	struct R_DATA *resource;
	unsigned char *rdata;
};

//Structure of a Query
typedef struct
{
	unsigned char *name;
	struct QUESTION *ques;
} QUERY;

int createDnsQueryBuffer(unsigned char* buf,int query_type,unsigned char *host){
	struct DNS_HEADER *dns = NULL;
	struct QUESTION *qinfo = NULL;
	unsigned char *qname = NULL;
	dns = (struct DNS_HEADER *)buf;
	dns->id = (unsigned short) htons(getpid());
	dns->qr = 0; //This is a query
	dns->opcode = 0; //This is a standard query
	dns->aa = 0; //Not Authoritative
	dns->tc = 0; //This message is not truncated
	dns->rd = 1; //Recursion Desired
	dns->ra = 0; //Recursion not available! hey we dont have it (lol)
	dns->z = 0;
	dns->ad = 0;
	dns->cd = 0;
	dns->rcode = 0;
	dns->q_count = htons(1); //we have only 1 question
	dns->ans_count = 0;
	dns->auth_count = 0;
	dns->add_count = 0;

	//point to the query portion
	qname =(unsigned char*)&buf[sizeof(struct DNS_HEADER)];

	DnsNameFormat(qname , host);
	qinfo =(struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)]; //fill it

	qinfo->qtype = htons( query_type ); //type of the query , A , MX , CNAME , NS etc
	qinfo->qclass = htons(1); //its internet (lol)

	return sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION);
}

void processDnsMsgBuffer(unsigned char* buf,int offset){
	struct DNS_HEADER *dns = NULL;
	unsigned char *reader;
	int i , j , stop , s;
	int isaddress = 0;
	struct RES_RECORD answers[20],auth[20],addit[20]; 

	dns = (struct DNS_HEADER*) buf;


	//move ahead of the dns header and the query field
	reader = &buf[offset];

	printf("\nThe response contains : ");
	printf("\n %d Answers.",ntohs(dns->ans_count));
	printf("\n %d Authoritative Servers.",ntohs(dns->auth_count));
	printf("\n %d Additional records.\n\n",ntohs(dns->add_count));

	//Start reading answers
	stop=0;

	for(i=0;i<ntohs(dns->ans_count);i++)
	{
		answers[i].name=ReadName(reader,buf,&stop);
		reader = reader + stop;

		answers[i].resource = (struct R_DATA*)(reader);
		reader = reader + sizeof(struct R_DATA);

		if(ntohs(answers[i].resource->type) == T_A||ntohs(answers[i].resource->type) == T_AAAA) //if its an ipv4 address
		{
			isaddress = 1;
			answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len)+10);

			for(j=0 ; j<ntohs(answers[i].resource->data_len) ; j++)
			{
				answers[i].rdata[j]=reader[j];
			}

			answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';

			reader = reader + ntohs(answers[i].resource->data_len);
		}
		else
		{
			answers[i].rdata = ReadName(reader,buf,&stop);
			reader = reader + stop;
		}
	}

	//read authorities
	for(i=0;i<ntohs(dns->auth_count);i++)
	{
		auth[i].name=ReadName(reader,buf,&stop);
		reader+=stop;

		auth[i].resource=(struct R_DATA*)(reader);
		reader+=sizeof(struct R_DATA);

		auth[i].rdata=ReadName(reader,buf,&stop);
		reader+=stop;
	}
	//read additional
	for(i=0;i<ntohs(dns->add_count);i++)
	{
		addit[i].name=ReadName(reader,buf,&stop);
		reader+=stop;
		addit[i].resource=(struct R_DATA*)(reader);
		reader+=sizeof(struct R_DATA);
		if(isaddress)
		{
			addit[i].rdata = (unsigned char*)malloc(ntohs(addit[i].resource->data_len));
			for(j=0;j<ntohs(addit[i].resource->data_len);j++)
			addit[i].rdata[j]=reader[j];
			addit[i].rdata[ntohs(addit[i].resource->data_len)]='\0';
			reader+=ntohs(addit[i].resource->data_len);
		}
		else
		{
			addit[i].rdata=ReadName(reader,buf,&stop);
			reader+=stop;
		}
	}

	//print answers
	printf("\nAnswer Records : %d \n" , ntohs(dns->ans_count) );
	for(i=0 ; i < ntohs(dns->ans_count) ; i++)
	{
		printf("Name : %s ",answers[i].name);

		if(ntohs(answers[i].resource->type) == T_A) //IPv4 address
		{
			long *p;
			p=(long*)answers[i].rdata;
			char str[100];
			printf("IPv4 address : %s",inet_ntop(AF_INET, p, str, 100));
		}else if(ntohs(answers[i].resource->type) == T_AAAA) //IPv4 address
		{
			long *p;
			p=(long*)answers[i].rdata;
			char str[100];
			printf("IPv6 address : %s",inet_ntop(AF_INET6, p, str, 100));
		}else if(ntohs(answers[i].resource->type)==T_CNAME) 
		{
			printf("has alias name : %s",answers[i].rdata);
		}
		printf("\n");
	}

	//print authorities
	printf("\nAuthoritive Records : %d \n" , ntohs(dns->auth_count) );
	for( i=0 ; i < ntohs(dns->auth_count) ; i++)
	{
		
		printf("Name : %s ",auth[i].name);
		if(ntohs(auth[i].resource->type)==2)
		{
			printf("has nameserver : %s",auth[i].rdata);
		}
		printf("\n");
	}

	//print additional resource records
	printf("\nAdditional Records : %d \n" , ntohs(dns->add_count) );
	for(i=0; i < ntohs(dns->add_count) ; i++)
	{
		printf("Name : %s ",addit[i].name);
		if(ntohs(addit[i].resource->type)==T_A)
		{
			long *p;
			p=(long*)addit[i].rdata;
			char str[100];
			printf("IPv4 address : %s",inet_ntop(AF_INET, p, str, 100));
		}else if(ntohs(addit[i].resource->type)==T_AAAA)
		{
			long *p;
			p=(long*)addit[i].rdata;
			char str[100];
			printf("IPv6 address : %s",inet_ntop(AF_INET6, p, str, 100));
		}
		printf("\n");
	}
}

void getHostByNameAndDNSServer(unsigned char *host,unsigned char* dns_server, int query_type)
{
	int updtodnsServer_socket_family = AF_INET;
	unsigned char buf[MAXBUFZISE],*qname,*reader;
	int i , j , stop , s;
	struct sockaddr_in* dest;
	struct sockaddr_in6 dest_ipv6;
	struct sockaddr_in dest_ipv4;
	int sendlen = 0;
	int serverlen = 0;
	int destSize = 0;
	serverlen = strlen(dns_server);
	for(i=0;i<serverlen;i++){
		if(dns_server[i]==':'){
			updtodnsServer_socket_family = AF_INET6;
			break;
		}
	}

	printf("Resolving %s" , host);
	s = socket(updtodnsServer_socket_family , SOCK_DGRAM , IPPROTO_UDP); //UDP packet for DNS queries

	if(updtodnsServer_socket_family == AF_INET6){
		
		dest_ipv6.sin6_family = AF_INET6;
		dest_ipv6.sin6_port = htons(53);
		struct in6_addr in6addr_MY;
		inet_pton(updtodnsServer_socket_family, dns_server, &in6addr_MY);
		dest_ipv6.sin6_addr =in6addr_MY;
		dest = &dest_ipv6;
		destSize = sizeof(dest_ipv6);
	}else{
		dest_ipv4.sin_family = AF_INET;
		dest_ipv4.sin_port = htons(53);
		struct in_addr inaddr_MY;
		inet_pton(updtodnsServer_socket_family, dns_server, &inaddr_MY);
		dest_ipv4.sin_addr =inaddr_MY;
		dest = &dest_ipv4;
		destSize = sizeof(dest_ipv4);
	}
	
	//Set the DNS structure to standard queries
	sendlen = createDnsQueryBuffer(buf,query_type,host);

	printf("\nSending Packet...");
	if( sendto(s,(char*)buf,sendlen,0,(struct sockaddr*)dest,destSize) < 0)
	{
		perror("sendto failed");
		return;
	}
	printf("Done");
	
	//Receive the answer
	i = sizeof dest;
	printf("\nReceiving answer...");
	if(recvfrom (s,(char*)buf , 65536 , 0 , (struct sockaddr*)dest , (socklen_t*)&destSize ) < 0)
	{
		perror("recvfrom failed");
		return;
	}
	printf("Done");
	processDnsMsgBuffer(buf,sendlen);	
	return;
}
/*
 * 
 * */
u_char* ReadName(unsigned char* reader,unsigned char* buffer,int* count)
{
	unsigned char *name;
	unsigned int p=0,jumped=0,offset;
	int i , j;

	*count = 1;
	name = (unsigned char*)malloc(256);

	name[0]='\0';

	//read the names in '0x03'www'0x04'xxxx'0x03'com  format
	while(*reader!=0)
	{
		if(*reader>=192)
		{
			offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000 ;)
			reader = buffer + offset - 1;
			jumped = 1; //we have jumped to another location so counting wont go up!
		}
		else
		{
			name[p++]=*reader;
		}

		reader = reader+1;

		if(jumped==0)
		{
			*count = *count + 1; //if we havent jumped to another location then we can count up
		}
	}

	name[p]='\0'; //string complete
	if(jumped==1)
	{
		*count = *count + 1; //number of steps we actually moved forward in the packet
	}

	HostNameFormat(name);
	//now convert 3www6google3com0 to www.google.com
	 //remove the last dot
	return name;
}

/*
 * convert '0x03'www'0x04'xxxx'0x03'com to www.xxxx.com 
 * */
void HostNameFormat(unsigned char* name) 
{
	int i = 0,j = 0,p = 0;
	for(i = 0 ; i < (int)strlen((const char*)name) ; i++) 
	{
		p = name[i];
		for(j=0;j<(int)p;j++) 
		{
			name[i] = name[i+1];
			i = i+1;
		}
		name[i] = '.';
	}
	name[i-1] = '\0';
}

/*
 * convert www.xxxx.com to '0x03'www'0x04'xxxx'0x03'com 
 * */
void DnsNameFormat(unsigned char* dns,unsigned char* host) 
{
	int lock = 0 , i;
	//www.xxxx.com->www.xxxx.com.
	strcat((char*)host,".");
	//.www.xxxx.com->'0x03'www'0x04'xxxx'0x03'com 
	for(i = 0 ; i < strlen((char*)host) ; i++) 
	{
		//i=3;8;12
		//lock=0,4,9,
		//i-3=3;4;3
		if(host[i]=='.')

		{
			*dns++ = i-lock;
			for(;lock<i;lock++) 
			{
				*dns++=host[lock];
			}
			lock++; 
		}
	}
	*dns++='\0';
}


int main( int argc , char *argv[])
{
	unsigned char hostname[100];
	unsigned char dnsServer[100];
	//Get the hostname from the terminal
	printf("Enter dns server : ");
	scanf("%s" , dnsServer);
	printf("Enter Hostname to Lookup : ");
	scanf("%s" , hostname);
	//get ipv4 address
	getHostByNameAndDNSServer(hostname,dnsServer,T_A);
	//get ipv6 address
	getHostByNameAndDNSServer(hostname,dnsServer,T_AAAA);
	
	return 0;
}
