#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<winsock2.h>
#include<ws2tcpip.h>
#include"mstcpip.h"
#pragma comment(lib,"ws2_32.lib")		/*链接API相关连的Ws2_32.lib静态库*/
#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1)  //

#define BUFFER_SIZE 65535

typedef struct _TCP{   /*TCP结构体*/
	WORD SrcPort; // 源端口
	WORD DstPort; // 目的端口
	DWORD SeqNum; // 顺序号
	DWORD AckNum; // 确认号
	BYTE DataOff; // TCP头长
	BYTE Flags; // 标志（URG、ACK等）
	WORD Window; // 窗口大小
	WORD Chksum; // 校验和
	WORD UrgPtr; // 紧急指针
} TCP;
typedef TCP *LPTCP;
typedef TCP UNALIGNED * ULPTCP;

typedef struct _IP{   /*IP头结构体*/
	union{ 
		BYTE Version; // 版本
		BYTE HdrLen; // 首部长度
	};
	BYTE ServiceType; // 服务类型
	WORD TotalLen; // 总长
	WORD ID; // 标识
	union{ WORD Flags; // 标志
		WORD FragOff; // 分段偏移
	};
	BYTE TimeToLive; // 生命期
	BYTE Protocol; // 协议
	WORD HdrChksum; // 头校验和
	DWORD SrcAddr; // 源地址
	DWORD DstAddr; // 目的地址
	BYTE Options; // 选项
} IP; 
typedef IP * LPIP;
typedef IP UNALIGNED * ULPIP;

char *GetICMPTypeTxt(int type) /*获取ICMP报文类型的文字描述*/
{
	switch(type)
	{
		case 3:
			return "差错报告报文中的终点不可达类型";
		case 4:
			return "差错报告报文中的源点抑制类型";
		case 5:
			return "差错报告报文中的改变路由类型";
		case 11:
			return "差错报告报文中的时间超过类型";
		case 12:
			return "差错报告报文中的参数问题类型";
		case 8:
			return "询问报文中的回送请求类型";
		case 0:
			return "询问报文中的回送回答类型";
		case 13:
			return "询问报文中的时间戳请求类型";
		case 14:
			return "询问报文中的时间戳回答类型";
	}
}

char *GetProtocolTxt(int Protocol) /*获取协议的名字*/
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
			return "任意主机内部协议";
		case 62:
			return "CFTP";
		case 63:
			return "任意本地网络";
		case 64:
			return "SAT-EXPAK";
		case 65:
			return "KRYPTOLAN";
		case 66:
			return "RVD";
		case 67:
			return "IPPC";
		case 68:
			return "任意分布式文件系统";
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
			return "任意专用加密方案";
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
			return "任意0跳协议";
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

void analysis(char *buffer)  /*解析IP数据报内容*/
{
	/*主要解析TCP,HTTP,HTTPS,SSH,SMTP,UDP,DNS,ICMP,IGMP*/
	IP ip;
	TCP tcp;
	ip = *(IP*)buffer;
	tcp = *(TCP*)(buffer+ (ip.HdrLen&0x0f)*4); //算出tcp头的开始位置
	if(ip.Protocol == 6) {  //TCP
		FILE *fp = fopen("log.txt","a");
		if(ntohs(tcp.SrcPort)==80 || ntohs(tcp.DstPort)==80){  //HTTP
			printf("协议：%s\n","HTTP");
			fprintf(fp,"协议：%s\n","HTTP");
		}else if(ntohs(tcp.SrcPort)==443 || ntohs(tcp.DstPort)==443) {  //HTTPS
			printf("协议：%s\n","HTTPS");
			fprintf(fp,"协议：%s\n","HTTPS");
		}else if(ntohs(tcp.SrcPort)==22 || ntohs(tcp.DstPort)==22) {  //SSH
			printf("协议：%s\n","SSH");
			fprintf(fp,"协议：%s\n","SSH");
		}else if(ntohs(tcp.SrcPort)==25 || ntohs(tcp.DstPort)==25) {   //SMTP
			printf("协议：%s\n","SMTP");
			fprintf(fp,"协议：%s\n","SMTP");
		}else{   //TCP
			printf("协议：%s\n","TCP");
			fprintf(fp,"协议：%s\n","TCP");
		}
		
		printf("源地址：%s\n",inet_ntoa(*(in_addr*)&ip.SrcAddr));
		printf("目的地址：%s\n",inet_ntoa(*(in_addr*)&ip.DstAddr));
		printf("数据包长度：%d\n",ntohs(ip.TotalLen));
		printf("源端口号：%d\n",ntohs(tcp.SrcPort));
		printf("目的端口号：%d\n",ntohs(tcp.DstPort)); 
		printf("\n");
		
		fprintf(fp,"源地址：%s\n",inet_ntoa(*(in_addr*)&ip.SrcAddr));
		fprintf(fp,"目的地址：%s\n",inet_ntoa(*(in_addr*)&ip.DstAddr));
		fprintf(fp,"数据包长度：%d\n",ntohs(ip.TotalLen));		
		fprintf(fp,"源端口号：%d\n",ntohs(tcp.SrcPort));
		fprintf(fp,"目的端口号：%d\n",ntohs(tcp.DstPort));
		fprintf(fp,"\n");
		fclose(fp);
		
	}else if(ip.Protocol == 17){  //UDP
		FILE *fp = fopen("log.txt","a");
		if(ntohs(tcp.SrcPort)==53 || ntohs(tcp.DstPort)==53){  //DNS
			printf("协议：%s\n","DNS");
			fprintf(fp,"协议：%s\n","DNS");
		}else{
			printf("协议：%s\n","UDP");
			fprintf(fp,"协议：%s\n","UDP");
		}
		
		printf("源地址：%s\n",inet_ntoa(*(in_addr*)&ip.SrcAddr));
		printf("目的地址：%s\n",inet_ntoa(*(in_addr*)&ip.DstAddr));
		printf("数据包长度：%d\n",ntohs(ip.TotalLen));
		printf("源端口号：%d\n",ntohs(tcp.SrcPort));
		printf("目的端口号：%d\n",ntohs(tcp.DstPort)); 
		printf("\n");
		
		fprintf(fp,"源地址：%s\n",inet_ntoa(*(in_addr*)&ip.SrcAddr));
		fprintf(fp,"目的地址：%s\n",inet_ntoa(*(in_addr*)&ip.DstAddr));
		fprintf(fp,"数据包长度：%d\n",ntohs(ip.TotalLen));		
		fprintf(fp,"源端口号：%d\n",ntohs(tcp.SrcPort));
		fprintf(fp,"目的端口号：%d\n",ntohs(tcp.DstPort));
		fprintf(fp,"\n");
		fclose(fp);
	}else if(ip.Protocol == 1) {  //ICMP
		int temp = (int)buffer[(ip.HdrLen&0x0f)*4];//计算ICMP报文的第一个字节位置

		printf("协议：%s\n","ICMP");
		printf("源地址：%s\n",inet_ntoa(*(in_addr*)&ip.SrcAddr));
		printf("目的地址：%s\n",inet_ntoa(*(in_addr*)&ip.DstAddr));
		printf("数据包长度：%d\n",ntohs(ip.TotalLen));
		printf("ICMP报文的类型：%s\n",GetICMPTypeTxt(temp));
		printf("\n");

		FILE *fp = fopen("log.txt","a");
		fprintf(fp,"协议：%s\n","ICMP");
		fprintf(fp,"源地址：%s\n",inet_ntoa(*(in_addr*)&ip.SrcAddr));
		fprintf(fp,"目的地址：%s\n",inet_ntoa(*(in_addr*)&ip.DstAddr));
		fprintf(fp,"数据包长度：%d\n",ntohs(ip.TotalLen));
		fprintf(fp,"ICMP报文的类型：%s\n",GetICMPTypeTxt(temp));
		fprintf(fp,"\n");
		fclose(fp);
	}else if(ip.Protocol == 2) {  //IGMP
		int temp = (int)buffer[(ip.HdrLen&0x0f)*4];//计算IGMP报文的第一个字节位置
		
		printf("协议：%s\n","IGMPV3");
		printf("源地址：%s\n",inet_ntoa(*(in_addr*)&ip.SrcAddr));
		printf("目的地址：%s\n",inet_ntoa(*(in_addr*)&ip.DstAddr));
		printf("数据包长度：%d\n",ntohs(ip.TotalLen));
		if(temp==0x11){
			printf("IGMP报文的类型：成员关系查询报文\n");
		}else{
			printf("IGMP报文的类型：成员关系报告报文\n");
		}
		printf("\n");

		FILE *fp = fopen("log.txt","a");
		fprintf(fp,"协议：%s\n","IGMPV3");
		fprintf(fp,"源地址：%s\n",inet_ntoa(*(in_addr*)&ip.SrcAddr));
		fprintf(fp,"目的地址：%s\n",inet_ntoa(*(in_addr*)&ip.DstAddr));
		fprintf(fp,"数据包长度：%d\n",ntohs(ip.TotalLen));
		if(temp==0x11){
			fprintf(fp,"IGMP报文的类型：成员关系查询报文\n");
		}else{
			fprintf(fp,"IGMP报文的类型：成员关系报告报文\n");
		}
		fprintf(fp,"\n");
		fclose(fp);
	}else {
		printf("协议：%s\n",GetProtocolTxt(ip.Protocol));
		printf("源地址：%s\n",inet_ntoa(*(in_addr*)&ip.SrcAddr));
		printf("目的地址：%s\n",inet_ntoa(*(in_addr*)&ip.DstAddr));
		printf("数据包长度：%d\n",ntohs(ip.TotalLen));
		printf("\n");

		FILE *fp = fopen("log.txt","a");
		fprintf(fp,"协议：%s\n",GetProtocolTxt(ip.Protocol));
		fprintf(fp,"源地址：%s\n",inet_ntoa(*(in_addr*)&ip.SrcAddr));
		fprintf(fp,"目的地址：%s\n",inet_ntoa(*(in_addr*)&ip.DstAddr));
		fprintf(fp,"数据包长度：%d\n",ntohs(ip.TotalLen));
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
	SOCKET sock = WSASocket(AF_INET,SOCK_RAW,IPPROTO_IP,NULL,0,WSA_FLAG_OVERLAPPED); ;//创建原始套接字
	if(sock == 0)
	{
		printf("创建套接字失败。");
		exit(1);
	}

	BOOL flag = TRUE;
	int a = setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char*)&flag, sizeof(flag));// 设置IP头操纵选项，其中flag 设置为ture，亲身对IP头进行处理
	if(a != 0)
	{
		printf("设置IP头自身处理失败");
		exit(2);
	}

	char LocalName[256];
	a = gethostname((char*)LocalName, sizeof(LocalName)-1);// 获取主机名
	if(a != 0)
	{
		printf("获取主机名失败:%s",WSAGetLastError());
		exit(3);
	}

	hostent *host = gethostbyname((char*)LocalName);//获取本机信息（包括IP）
	if(host == NULL)
	{
		printf("获取本机IP失败:%s",WSAGetLastError());
		exit(4);
	}

	memset(&addr_in,0,sizeof(addr_in));
	addr_in.sin_addr = *(in_addr *)host->h_addr_list[0]; //IP
	addr_in.sin_family = AF_INET;
	addr_in.sin_port = htons(57274);
	bind(sock, (LPSOCKADDR)&addr_in, sizeof(addr_in)); //把原始套接字sock 绑定到本地网卡地址上

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
			printf("接收出现错误:%s",WSAGetLastError());
			continue;
		}
		else if(res>0)
		{
			//接收到数据包
			analysis(buffer);  
		}
	}  

	printf("%s\n",LocalName);//打印主机名
	printf("%s\n",inet_ntoa(*(in_addr*)&host->h_addr_list[0])); //打印ip地址
	printf("%d,%d\n",a,sock);
	return 0;
}
