#include <pcap.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

struct _ {
	int num;
	char ip[200];
};
struct _ count[1000];
int t=0;

void getPacket(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)
{
	int * id = (int *)arg,i;
	char tmp[200];
	
	printf("id: %d\n", ++(*id));
	printf("Time Mark: %s", ctime((const time_t *)&pkthdr->ts.tv_sec)); 
	printf("MAC Address From: ");
	for(i=6;i<12;i++)
		printf("%02x ",packet[i]);
	printf("\n");
	
	printf("MAC Adress To: ");
	for(i=0;i<6;i++)
		printf("%02x ",packet[i]);
	printf("\n");
	
	int type1=packet[12],type2=packet[13];
	
	if(type1==8&&type2==0)//IP
	{
		printf("Type: IP\n");
		
		printf("Source IP Address: ");
		for(i=26;i<29;i++)
			printf("%d.",packet[i]);		
		printf("%d\n",packet[29]);
		
		printf("Destination IP Address: ");
		for(i=30;i<33;i++)
			printf("%d.",packet[i]);
		printf("%d\n",packet[33]);

		printf("Protocol type: ");
		if(packet[23]==6)
			printf("TCP\n");
		else if(packet[23]==17)
			printf("UDP\n");
		else 
			printf("else\n");
			
		if(packet[23]==6||packet[23]==17){
			printf("Source port: %d\n",packet[34]*256+packet[35]);
			printf("Destination port: %d\n",packet[36]*256+packet[37]);
		}
		sprintf(tmp,"[%d.%d.%d.%d] to [%d.%d.%d.%d]\0",packet[26],packet[27],packet[28],packet[29],packet[30],packet[31],packet[32],packet[33]);
		
		int flag=0;
		for(i=0;i<t;i++)
		{
			if(strcmp(count[i].ip,tmp)==0)
			{
				flag=1;
				count[i].num++;
				break;
			}
		}
		if(flag==0)
		{
			count[t].num=1;
			strcpy(count[t].ip,tmp);
			t++;
		}
	}
	printf("\n\n");
}

int main(int argc ,char *argv[])
{
	int n=-1;
	char ErrorBuffer[PCAP_ERRBUF_SIZE], * deviceString,filename[100]="";
	memset(count,0,sizeof(count));
	
	/* get a device */
	deviceString = pcap_lookupdev(ErrorBuffer);

	if(deviceString)
	{
		printf("device is : %s\n", deviceString);
	}
	else
	{
		printf("error: %s\n", ErrorBuffer);
		exit(1);
	}

	pcap_t *device = pcap_open_live(deviceString, 65535, 1, 0, ErrorBuffer);
	if(argc==2)
	{
		strcpy(filename,argv[1]);
		device = pcap_open_offline(filename, ErrorBuffer);
		if(!device) {
			fprintf(stderr, "pcap_open_offline(): %s\n", ErrorBuffer);
			exit(1);
		}
		printf("Open: %s\n", filename);
	}


	int id = 0,i;
	pcap_loop(device, n, getPacket, (u_char*)&id);
	printf("--------------------------------------\n");
	for(i=0;i<t;i++)
		printf("%s  %d\n",count[i].ip,count[i].num);
	pcap_close(device);

	return 0;
}
