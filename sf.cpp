#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<winsock2.h>
#include<ws2tcpip.h>
#include"mstcpip.h"
#pragma comment(lib,"ws2_32.lib")		/*����API�������Ws2_32.lib��̬��*/
#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1)  //

#define BUFFER_SIZE 65535

typedef struct _TCP{   /*TCP�ṹ��*/
	WORD SrcPort; // Դ�˿�
	WORD DstPort; // Ŀ�Ķ˿�
	DWORD SeqNum; // ˳���
	DWORD AckNum; // ȷ�Ϻ�
	BYTE DataOff; // TCPͷ��
	BYTE Flags; // ��־��URG��ACK�ȣ�
	WORD Window; // ���ڴ�С
	WORD Chksum; // У���
	WORD UrgPtr; // ����ָ��
} TCP;
typedef TCP *LPTCP;
typedef TCP UNALIGNED * ULPTCP;

typedef struct _IP{   /*IPͷ�ṹ��*/
	union{ 
		BYTE Version; // �汾
		BYTE HdrLen; // �ײ�����
	};
	BYTE ServiceType; // ��������
	WORD TotalLen; // �ܳ�
	WORD ID; // ��ʶ
	union{ WORD Flags; // ��־
		WORD FragOff; // �ֶ�ƫ��
	};
	BYTE TimeToLive; // ������
	BYTE Protocol; // Э��
	WORD HdrChksum; // ͷУ���
	DWORD SrcAddr; // Դ��ַ
	DWORD DstAddr; // Ŀ�ĵ�ַ
	BYTE Options; // ѡ��
} IP; 
typedef IP * LPIP;
typedef IP UNALIGNED * ULPIP;

char *GetICMPTypeTxt(int type) /*��ȡICMP�������͵���������*/
{
	switch(type)
	{
		case 3:
			return "����汨���е��յ㲻�ɴ�����";
		case 4:
			return "����汨���е�Դ����������";
		case 5:
			return "����汨���еĸı�·������";
		case 11:
			return "����汨���е�ʱ�䳬������";
		case 12:
			return "����汨���еĲ�����������";
		case 8:
			return "ѯ�ʱ����еĻ�����������";
		case 0:
			return "ѯ�ʱ����еĻ��ͻش�����";
		case 13:
			return "ѯ�ʱ����е�ʱ�����������";
		case 14:
			return "ѯ�ʱ����е�ʱ����ش�����";
	}
}

char *GetProtocolTxt(int Protocol) /*��ȡЭ�������*/
{
	switch(Protocol)
	{
		case 0:
			return "HOPOPT";
		case 1:
			return "ICMP";
		case 2:
			return "IGMP";
		case 3:
			return "GGP";
		case 4:
			return "IP";
		case 5:
			return "ST";
		case 6:
			return "TCP";
		case 7:
			return "CBT";
		case 8:
			return "EGP";
		case 9:
			return "IGP";
		case 10:
			return "BBN-RCC-MON";
		case 11:
			return "NVP-II";
		case 12:
			return "PUP";
		case 13:
			return "ARGUS";
		case 14:
			return "EMCON";
		case 15:
			return "XNET";
		case 16:
			return "CHAOS";
		case 17:
			return "UDP";
		case 18:
			return "MUX";
		case 19:
			return "DCN-MEAS";
		case 20:
			return "HMP";
		case 21:
			return "PRM";
		case 22:
			return "XNS-IDP";
		case 23:
			return "TRUNK-1";
		case 24:
			return "TRUNK-2";
		case 25:
			return "LEAF-1";
		case 26:
			return "LEAF-2";
		case 27:
			return "RDP";
		case 28:
			return "IRTP";
		case 29:
			return "ISO-TP4";
		case 30:
			return "NETBLT";
		case 31:
			return "MFE-NSP";
		case 32:
			return "MERIT-INP";
		case 33:
			return "SEP";
		case 34:
			return "3PC";
		case 35:
			return "IDPR";
		case 36:
			return "XTP";
		case 37:
			return "DDP";
		case 38:
			return "IDPR-CMTP";
		case 39:
			return "TP++";
		case 40:
			return "IL";
		case 41:
			return "IPv6";
		case 42:
			return "SDRP";
		case 43:
			return "IPv6-Route";
		case 44:
			return "IPv6-Frag";
		case 45:
			return "IDRP";
		case 46:
			return "RSVP";
		case 47:
			return "GRE";
		case 48:
			return "MHRP";
		case 49:
			return "BNA";
		case 50:
			return "ESP";
		case 51:
			return "AH";
		case 52:
			return "I-NLSP";
		case 53:
			return "SWIPE";
		case 54:
			return "NARP";
		case 55:
			return "MOBILE";
		case 56:
			return "TLSP";
		case 57:
			return "SKIP";
		case 58:
			return "IPv6-ICMP";
		case 59:
			return "IPv6-NoNet";
		case 60:
			return "IPv6-Opts";
		case 61:
			return "���������ڲ�Э��";
		case 62:
			return "CFTP";
		case 63:
			return "���Ȿ������";
		case 64:
			return "SAT-EXPAK";
		case 65:
			return "KRYPTOLAN";
		case 66:
			return "RVD";
		case 67:
			return "IPPC";
		case 68:
			return "����ֲ�ʽ�ļ�ϵͳ";
		case 69:
			return "SAT-MON";
		case 70:
			return "VISA";
		case 71:
			return "IPCV";
		case 72:
			return "CPNX";
		case 73:
			return "CPHB";
		case 74:
			return "WSN";
		case 75:
			return "PVP";
		case 76:
			return "BR-SAT-MON";
		case 77:
			return "SUN-ND";
		case 78:
			return "WB-MON";
		case 79:
			return "WB-EXPAK";
		case 80:
			return "ISO-IP";
		case 81:
			return "VMTP";
		case 82:
			return "SECURE-VMTP";
		case 83:
			return "VINES";
		case 84:
			return "TTP";
		case 85:
			return "NSFNET-IGP";
		case 86:
			return "DGP";
		case 87:
			return "TCF";
		case 88:
			return "EIGRP";
		case 89:
			return "OSPFIGP";
		case 90:
			return "Sprite-RPC";
		case 91:
			return "LARP";
		case 92:
			return "MTP";
		case 93:
			return "AX.25";
		case 94:
			return "IPIP";
		case 95:
			return "MICP";
		case 96:
			return "SCC-SP";
		case 97:
			return "ETHERIP";
		case 98:
			return "ENCAP";
		case 99:
			return "����ר�ü��ܷ���";
		case 100:
			return "GMTP";
		case 101:
			return "IFMP";
		case 102:
			return "PNNI";
		case 103:
			return "PIM";
		case 104:
			return "ARIS";
		case 105:
			return "SCPS";
		case 106:
			return "QNX";
		case 107:
			return "A/N";
		case 108:
			return "IPComp";
		case 109:
			return "SNP";
		case 110:
			return "Compaq-Peer";
		case 111:
			return "IPX-in-IP";
		case 112:
			return "VRRP";
		case 113:
			return "PGM";
		case 114:
			return "����0��Э��";
		case 115:
			return "L2TP";
		case 116:
			return "DDX";
		case 117:
			return "IATP";
		case 118:
			return "STP";
		case 119:
			return "SRP";
		case 120:
			return "UTI";
		case 121:
			return "SMP";
		case 122:
			return "SM";
		case 123:
			return "PTP";
		case 124:
			return "ISIS";
		case 125:
			return "FIRE";
		case 126:
			return "CRTP";
		case 127:
			return "CRUDP";
		case 128:
			return "SSCOPMCE";
		case 129:
			return "IPLT";
		case 130:
			return "SPS";
		case 131:
			return "PIPE";
		case 132:
			return "SCTP";
		case 133:
			return "FC";
		default:
			return "NOKNOW";
	}
}

void analysis(char *buffer)  /*����IP���ݱ�����*/
{
	/*��Ҫ����TCP,HTTP,HTTPS,SSH,SMTP,UDP,DNS,ICMP,IGMP*/
	IP ip;
	TCP tcp;
	ip = *(IP*)buffer;
	tcp = *(TCP*)(buffer+ (ip.HdrLen&0x0f)*4); //���tcpͷ�Ŀ�ʼλ��
	if(ip.Protocol == 6) {  //TCP
		FILE *fp = fopen("log.txt","a");
		if(ntohs(tcp.SrcPort)==80 || ntohs(tcp.DstPort)==80){  //HTTP
			printf("Э�飺%s\n","HTTP");
			fprintf(fp,"Э�飺%s\n","HTTP");
		}else if(ntohs(tcp.SrcPort)==443 || ntohs(tcp.DstPort)==443) {  //HTTPS
			printf("Э�飺%s\n","HTTPS");
			fprintf(fp,"Э�飺%s\n","HTTPS");
		}else if(ntohs(tcp.SrcPort)==22 || ntohs(tcp.DstPort)==22) {  //SSH
			printf("Э�飺%s\n","SSH");
			fprintf(fp,"Э�飺%s\n","SSH");
		}else if(ntohs(tcp.SrcPort)==25 || ntohs(tcp.DstPort)==25) {   //SMTP
			printf("Э�飺%s\n","SMTP");
			fprintf(fp,"Э�飺%s\n","SMTP");
		}else{   //TCP
			printf("Э�飺%s\n","TCP");
			fprintf(fp,"Э�飺%s\n","TCP");
		}
		
		printf("Դ��ַ��%s\n",inet_ntoa(*(in_addr*)&ip.SrcAddr));
		printf("Ŀ�ĵ�ַ��%s\n",inet_ntoa(*(in_addr*)&ip.DstAddr));
		printf("���ݰ����ȣ�%d\n",ntohs(ip.TotalLen));
		printf("Դ�˿ںţ�%d\n",ntohs(tcp.SrcPort));
		printf("Ŀ�Ķ˿ںţ�%d\n",ntohs(tcp.DstPort)); 
		printf("\n");
		
		fprintf(fp,"Դ��ַ��%s\n",inet_ntoa(*(in_addr*)&ip.SrcAddr));
		fprintf(fp,"Ŀ�ĵ�ַ��%s\n",inet_ntoa(*(in_addr*)&ip.DstAddr));
		fprintf(fp,"���ݰ����ȣ�%d\n",ntohs(ip.TotalLen));		
		fprintf(fp,"Դ�˿ںţ�%d\n",ntohs(tcp.SrcPort));
		fprintf(fp,"Ŀ�Ķ˿ںţ�%d\n",ntohs(tcp.DstPort));
		fprintf(fp,"\n");
		fclose(fp);
		
	}else if(ip.Protocol == 17){  //UDP
		FILE *fp = fopen("log.txt","a");
		if(ntohs(tcp.SrcPort)==53 || ntohs(tcp.DstPort)==53){  //DNS
			printf("Э�飺%s\n","DNS");
			fprintf(fp,"Э�飺%s\n","DNS");
		}else{
			printf("Э�飺%s\n","UDP");
			fprintf(fp,"Э�飺%s\n","UDP");
		}
		
		printf("Դ��ַ��%s\n",inet_ntoa(*(in_addr*)&ip.SrcAddr));
		printf("Ŀ�ĵ�ַ��%s\n",inet_ntoa(*(in_addr*)&ip.DstAddr));
		printf("���ݰ����ȣ�%d\n",ntohs(ip.TotalLen));
		printf("Դ�˿ںţ�%d\n",ntohs(tcp.SrcPort));
		printf("Ŀ�Ķ˿ںţ�%d\n",ntohs(tcp.DstPort)); 
		printf("\n");
		
		fprintf(fp,"Դ��ַ��%s\n",inet_ntoa(*(in_addr*)&ip.SrcAddr));
		fprintf(fp,"Ŀ�ĵ�ַ��%s\n",inet_ntoa(*(in_addr*)&ip.DstAddr));
		fprintf(fp,"���ݰ����ȣ�%d\n",ntohs(ip.TotalLen));		
		fprintf(fp,"Դ�˿ںţ�%d\n",ntohs(tcp.SrcPort));
		fprintf(fp,"Ŀ�Ķ˿ںţ�%d\n",ntohs(tcp.DstPort));
		fprintf(fp,"\n");
		fclose(fp);
	}else if(ip.Protocol == 1) {  //ICMP
		int temp = (int)buffer[(ip.HdrLen&0x0f)*4];//����ICMP���ĵĵ�һ���ֽ�λ��

		printf("Э�飺%s\n","ICMP");
		printf("Դ��ַ��%s\n",inet_ntoa(*(in_addr*)&ip.SrcAddr));
		printf("Ŀ�ĵ�ַ��%s\n",inet_ntoa(*(in_addr*)&ip.DstAddr));
		printf("���ݰ����ȣ�%d\n",ntohs(ip.TotalLen));
		printf("ICMP���ĵ����ͣ�%s\n",GetICMPTypeTxt(temp));
		printf("\n");

		FILE *fp = fopen("log.txt","a");
		fprintf(fp,"Э�飺%s\n","ICMP");
		fprintf(fp,"Դ��ַ��%s\n",inet_ntoa(*(in_addr*)&ip.SrcAddr));
		fprintf(fp,"Ŀ�ĵ�ַ��%s\n",inet_ntoa(*(in_addr*)&ip.DstAddr));
		fprintf(fp,"���ݰ����ȣ�%d\n",ntohs(ip.TotalLen));
		fprintf(fp,"ICMP���ĵ����ͣ�%s\n",GetICMPTypeTxt(temp));
		fprintf(fp,"\n");
		fclose(fp);
	}else if(ip.Protocol == 2) {  //IGMP
		int temp = (int)buffer[(ip.HdrLen&0x0f)*4];//����IGMP���ĵĵ�һ���ֽ�λ��
		
		printf("Э�飺%s\n","IGMPV3");
		printf("Դ��ַ��%s\n",inet_ntoa(*(in_addr*)&ip.SrcAddr));
		printf("Ŀ�ĵ�ַ��%s\n",inet_ntoa(*(in_addr*)&ip.DstAddr));
		printf("���ݰ����ȣ�%d\n",ntohs(ip.TotalLen));
		if(temp==0x11){
			printf("IGMP���ĵ����ͣ���Ա��ϵ��ѯ����\n");
		}else{
			printf("IGMP���ĵ����ͣ���Ա��ϵ���汨��\n");
		}
		printf("\n");

		FILE *fp = fopen("log.txt","a");
		fprintf(fp,"Э�飺%s\n","IGMPV3");
		fprintf(fp,"Դ��ַ��%s\n",inet_ntoa(*(in_addr*)&ip.SrcAddr));
		fprintf(fp,"Ŀ�ĵ�ַ��%s\n",inet_ntoa(*(in_addr*)&ip.DstAddr));
		fprintf(fp,"���ݰ����ȣ�%d\n",ntohs(ip.TotalLen));
		if(temp==0x11){
			fprintf(fp,"IGMP���ĵ����ͣ���Ա��ϵ��ѯ����\n");
		}else{
			fprintf(fp,"IGMP���ĵ����ͣ���Ա��ϵ���汨��\n");
		}
		fprintf(fp,"\n");
		fclose(fp);
	}else {
		printf("Э�飺%s\n",GetProtocolTxt(ip.Protocol));
		printf("Դ��ַ��%s\n",inet_ntoa(*(in_addr*)&ip.SrcAddr));
		printf("Ŀ�ĵ�ַ��%s\n",inet_ntoa(*(in_addr*)&ip.DstAddr));
		printf("���ݰ����ȣ�%d\n",ntohs(ip.TotalLen));
		printf("\n");

		FILE *fp = fopen("log.txt","a");
		fprintf(fp,"Э�飺%s\n",GetProtocolTxt(ip.Protocol));
		fprintf(fp,"Դ��ַ��%s\n",inet_ntoa(*(in_addr*)&ip.SrcAddr));
		fprintf(fp,"Ŀ�ĵ�ַ��%s\n",inet_ntoa(*(in_addr*)&ip.DstAddr));
		fprintf(fp,"���ݰ����ȣ�%d\n",ntohs(ip.TotalLen));
		fprintf(fp,"\n");
		fclose(fp);
	}
	
}

int main()
{

	int i;
	char buffer[BUFFER_SIZE];
	struct sockaddr_in addr_in;
	WSADATA WSAData;
	IP ip;
	TCP tcp;
	WSAStartup(MAKEWORD(2, 2), &WSAData);
	SOCKET sock = WSASocket(AF_INET,SOCK_RAW,IPPROTO_IP,NULL,0,WSA_FLAG_OVERLAPPED); ;//����ԭʼ�׽���
	if(sock == 0)
	{
		printf("�����׽���ʧ�ܡ�");
		exit(1);
	}

	BOOL flag = TRUE;
	int a = setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char*)&flag, sizeof(flag));// ����IPͷ����ѡ�����flag ����Ϊture�������IPͷ���д���
	if(a != 0)
	{
		printf("����IPͷ������ʧ��");
		exit(2);
	}

	char LocalName[256];
	a = gethostname((char*)LocalName, sizeof(LocalName)-1);// ��ȡ������
	if(a != 0)
	{
		printf("��ȡ������ʧ��:%s",WSAGetLastError());
		exit(3);
	}

	hostent *host = gethostbyname((char*)LocalName);//��ȡ������Ϣ������IP��
	if(host == NULL)
	{
		printf("��ȡ����IPʧ��:%s",WSAGetLastError());
		exit(4);
	}

	memset(&addr_in,0,sizeof(addr_in));
	addr_in.sin_addr = *(in_addr *)host->h_addr_list[0]; //IP
	addr_in.sin_family = AF_INET;
	addr_in.sin_port = htons(57274);
	bind(sock, (LPSOCKADDR)&addr_in, sizeof(addr_in)); //��ԭʼ�׽���sock �󶨵�����������ַ��

	DWORD dwBufferLen[10]; 
	DWORD dwBufferInLen = 1; 
	DWORD dwBytesReturned = 0; 
	WSAIoctl(sock, SIO_RCVALL,&dwBufferInLen, sizeof(dwBufferInLen), &dwBufferLen, sizeof(dwBufferLen),&dwBytesReturned , NULL , NULL ); 
	
	while(1)
	{
		memset(&ip, 0, sizeof(ip));
		memset(&tcp, 0, sizeof(tcp));
		memset(buffer, 0, sizeof(buffer));
		int res = recv(sock, buffer, BUFFER_SIZE, 0);
		if(res == SOCKET_ERROR)
		{
			printf("���ճ��ִ���:%s",WSAGetLastError());
			continue;
		}
		else if(res>0)
		{
			//���յ����ݰ�
			analysis(buffer);  
		}
	}  

	printf("%s\n",LocalName);//��ӡ������
	printf("%s\n",inet_ntoa(*(in_addr*)&host->h_addr_list[0])); //��ӡip��ַ
	printf("%d,%d\n",a,sock);
	return 0;
}
