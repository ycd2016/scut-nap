#include "auth.h"
#include "tracelog.h"
#include "info.h"
struct in_addr local_ipaddr;
uint8_t MAC[6];
#define DRCOM_UDP_HEARTBEAT_DELAY  12
#define DRCOM_UDP_HEARTBEAT_TIMEOUT 2
#define DRCOM_UDP_RECV_DELAY  2
#define AUTH_8021X_LOGOFF_DELAY 500000
#define AUTH_8021X_RECV_DELAY  1
#define AUTH_8021X_RECV_TIMES  3
const static uint8_t BroadcastAddr[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
const static uint8_t MultcastAddr[6] = { 0x01, 0x80, 0xc2, 0x00, 0x00, 0x03 };
const static uint8_t UnicastAddr[6] = { 0x01, 0xd0, 0xf8, 0x00, 0x00, 0x03 };
static uint8_t send_8021x_data[1024];
static size_t send_8021x_data_len = 0;
static uint8_t send_udp_data[ETH_FRAME_LEN];
static uint8_t recv_udp_data[ETH_FRAME_LEN];
static int send_udp_data_len = 0;
static int resev = 0;
static int times = AUTH_8021X_RECV_TIMES;
static int success_8021x = 0;
static int isNeedHeartBeat = 0;
static uint8_t EthHeader[14] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
								 0x00, 0x00, 0x00, 0x00, 0x88, 0x8e };
static uint8_t BroadcastHeader[14] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff,
									   0xff, 0xff, 0xff, 0xff, 0xff, 0x88, 0x8e };
static uint8_t MultcastHeader[14] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
									  0x80, 0xc2, 0x00, 0x00, 0x03, 0x88, 0x8e };
static uint8_t UnicastHeader[14] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
									 0xd0, 0xf8, 0x00, 0x00, 0x03, 0x88, 0x8e };
static time_t BaseHeartbeatTime = 0;
static int auth_8021x_sock = 0;
static int auth_udp_sock = 0;
static uint8_t lastHBDone = 1;
struct sockaddr_ll auth_8021x_addr;
typedef enum {
	REQUEST = 1, RESPONSE = 2, SUCCESS = 3, FAILURE = 4, H3CDATA = 10
} EAP_Code;
typedef enum {
	IDENTITY = 1,
	NOTIFICATION = 2,
	MD5 = 4,
	AVAILABLE = 20,
	ALLOCATED_0x07 = 7,
	ALLOCATED_0x08 = 8
} EAP_Type;
typedef uint8_t EAP_ID;
struct sockaddr_in serv_addr, local_addr;
int chkIfUp(int sock) {
	struct ifreq ifr;
	bzero(&ifr, sizeof(ifr));
	strncpy(ifr.ifr_name, DeviceName, IFNAMSIZ - 1);
	if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
		LogWrite(INIT, ERROR, "ioctl get if_flag error: %s", strerror(errno));
		return -1;
	}
	if (ifr.ifr_ifru.ifru_flags & IFF_RUNNING) {
		LogWrite(INIT, INF, "%s link up.", DeviceName);
		return 0;
	}
	else {
		LogWrite(INIT, ERROR, "%s link down. Please check it.", DeviceName);
		return -1;
	}
}
int getIfIndex(int sock) {
	struct ifreq ifr;
	bzero(&ifr, sizeof(ifr));
	strncpy(ifr.ifr_name, DeviceName, IFNAMSIZ - 1);
	if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
		LogWrite(INIT, ERROR, "Get interface index error: %s", strerror(errno));
		return -1;
	}
	return ifr.ifr_ifindex;
}
int getIfIP(int sock) {
	struct ifreq ifr;
	bzero(&ifr, sizeof(ifr));
	strncpy(ifr.ifr_name, DeviceName, IFNAMSIZ - 1);
	ifr.ifr_addr.sa_family = AF_INET;
	if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
		LogWrite(INIT, ERROR, "Unable to get IP address of %s: %s", DeviceName,
			strerror(errno));
		return -1;
	}
	local_ipaddr = (((struct sockaddr_in*) & ifr.ifr_addr)->sin_addr);
	return 0;
}
int getIfMAC(int sock) {
	struct ifreq ifr;
	bzero(&ifr, sizeof(ifr));
	strncpy(ifr.ifr_name, DeviceName, IFNAMSIZ - 1);
	ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
	if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
		LogWrite(INIT, ERROR, "Unable to get MAC address of %s: %s", DeviceName,
			strerror(errno));
		return -1;
	}
	memcpy(MAC, ifr.ifr_hwaddr.sa_data, 6);
	return 0;
}
int auth_8021x_Init() {
	int optv = 1;
	int ret = 0;
	auth_8021x_sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_PAE));
	if (auth_8021x_sock < 0) {
		LogWrite(DOT1X, ERROR, "Unable to create raw socket: %s",
			strerror(errno));
		return auth_8021x_sock;
	}
	if ((ret = setsockopt(auth_8021x_sock, SOL_SOCKET, SO_REUSEADDR, &optv,
		sizeof(optv))) < 0) {
		LogWrite(DOT1X, ERROR, "setsockopt failed: %s", strerror(errno));
		goto ERR;
	}
	if ((ret = chkIfUp(auth_8021x_sock)) < 0) {
		goto ERR;
	}
	if ((ret = getIfMAC(auth_8021x_sock)) < 0) {
		goto ERR;
	}
	if ((ret = getIfIndex(auth_8021x_sock)) < 0) {
		goto ERR;
	}
	bzero(&auth_8021x_addr, sizeof(auth_8021x_addr));
	auth_8021x_addr.sll_ifindex = ret;
	auth_8021x_addr.sll_family = PF_PACKET;
	auth_8021x_addr.sll_protocol = htons(ETH_P_PAE);
	auth_8021x_addr.sll_pkttype = PACKET_HOST;
	return 0;
ERR:
	close(auth_8021x_sock);
	return ret;
}
int auth_8021x_Logoff() {
	struct timeval timeout = { 0, AUTH_8021X_LOGOFF_DELAY };
	struct timeval tmp_timeout = timeout;
	fd_set fdR;
	uint8_t recv_8021x_buf[ETH_FRAME_LEN] = { 0 };
	uint8_t LogoffCnt = 2;
	int ret = 0;
	LogWrite(DOT1X, INF, "Client: Send Logoff.");
	while (LogoffCnt--) {
		send_8021x_data_len = AppendDrcomLogoffPkt(MultcastHeader, send_8021x_data);
		LogWrite(DOT1X, DEBUG, "Sending logoff packet.");
		auth_8021x_Sender(send_8021x_data, send_8021x_data_len);
		FD_ZERO(&fdR);
		FD_SET(auth_8021x_sock, &fdR);
		tmp_timeout = timeout;
		switch (select(auth_8021x_sock + 1, &fdR, NULL, NULL, &tmp_timeout)) {
		case -1:
			LogWrite(DOT1X, ERROR, "Logoff: select socket failed: %s",
				strerror(errno));
			return -1;
			break;
		case 0:
			break;
		default:
			if (FD_ISSET(auth_8021x_sock, &fdR)) {
				if (auth_8021x_Receiver(recv_8021x_buf)) {
					if ((EAP_Code)recv_8021x_buf[18] == FAILURE) {
						LogWrite(DOT1X, INF, "Logged off.");
						ret = 1;
					}
				}
			}
			break;
		}
	}
	return ret;
}
int auth_UDP_Init() {
	int on = 1;
	auth_udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (auth_udp_sock < 0) {
		LogWrite(DRCOM, ERROR, "Create UDP socket failed: %s", strerror(errno));
		return auth_udp_sock;
	}
	if ((setsockopt(auth_udp_sock, SOL_SOCKET, SO_REUSEADDR | SO_BROADCAST, &on,
		sizeof(on))) < 0) {
		LogWrite(DRCOM, ERROR, "UDP setsockopt failed: %s", strerror(errno));
		close(auth_udp_sock);
		return -1;
	}
	if ((setsockopt(auth_udp_sock, SOL_SOCKET, SO_BINDTODEVICE, DeviceName,
		strlen(DeviceName))) < 0) {
		LogWrite(DRCOM, ERROR, "Bind UDP socket to device failed: %s", strerror(errno));
		close(auth_udp_sock);
		return -1;
	}
	bzero(&serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr = udpserver_ipaddr;
	serv_addr.sin_port = htons(SERVER_PORT);
	bzero(&local_addr, sizeof(local_addr));
	local_addr.sin_family = AF_INET;
	local_addr.sin_addr = local_ipaddr;
	local_addr.sin_port = htons(SERVER_PORT);
	if (bind(auth_udp_sock, (struct sockaddr*) & (local_addr),
		sizeof(local_addr)) < 0) {
		LogWrite(DRCOM, ERROR, "Bind UDP socket to IP failed: %s", strerror(errno));
		close(auth_udp_sock);
		return -1;
	}
	return 0;
}
int auth_UDP_Sender(uint8_t* send_data, int send_data_len) {
	if (sendto(auth_udp_sock, send_data, send_data_len, 0,
		(struct sockaddr*) & serv_addr, sizeof(serv_addr)) != send_data_len) {
		LogWrite(DRCOM, ERROR, "auth_UDP_Sender error: %s", strerror(errno));
		return 0;
	}
	PrintHex(DRCOM, "Packet sent", send_data, send_data_len);
	return 1;
}
int auth_UDP_Receiver(uint8_t* recv_data) {
	struct sockaddr_in clntaddr;
	socklen_t addrlen = sizeof(struct sockaddr_in);
	int recv_len;
	recv_len = recvfrom(auth_udp_sock, recv_data, ETH_FRAME_LEN, 0,
		(struct sockaddr*) & clntaddr, &addrlen);
	if (recv_len > 0 && memcmp(&clntaddr.sin_addr, &serv_addr.sin_addr, 4) == 0
		&& ((recv_data[0] == 0x07) || ((recv_data[0] == 0x4d)
			&& (recv_data[1] == 0x38)))) {
		PrintHex(DRCOM, "Packet received", recv_data, recv_len);
		return 1;
	}
	return 0;
}
int auth_8021x_Sender(uint8_t* send_data, int send_data_len) {
	if (sendto(auth_8021x_sock, send_data, send_data_len, 0,
		(struct sockaddr*) & auth_8021x_addr,
		sizeof(auth_8021x_addr)) != send_data_len) {
		LogWrite(DOT1X, ERROR, "auth_8021x_Sender error: %s", strerror(errno));
		return 0;
	}
	PrintHex(DOT1X, "Packet sent", send_data, send_data_len);
	return 1;
}
int auth_8021x_Receiver(uint8_t* recv_data) {
	struct ethhdr* recv_hdr;
	struct ethhdr* local_ethhdr;
	local_ethhdr = (struct ethhdr*) EthHeader;
	int recv_len = recv(auth_8021x_sock, recv_data, ETH_FRAME_LEN, 0);
	recv_hdr = (struct ethhdr*) recv_data;
	if (recv_len > 0
		&& (0 == memcmp(recv_hdr->h_dest, local_ethhdr->h_source, ETH_ALEN))
		&& (htons(ETH_P_PAE) == recv_hdr->h_proto)) {
		PrintHex(DOT1X, "Packet received", recv_data, recv_len);
		return 1;
	}
	return 0;
}
size_t appendStartPkt(uint8_t header[]) {
	return AppendDrcomStartPkt(header, send_8021x_data);
}
size_t appendResponseIdentity(const uint8_t request[]) {
	return AppendDrcomResponseIdentity(request, EthHeader, UserName,
		send_8021x_data);
}
size_t appendResponseMD5(const uint8_t request[]) {
	return AppendDrcomResponseMD5(request, EthHeader, UserName, Password,
		send_8021x_data);
}
void initAuthenticationInfo() {
	memcpy(MultcastHeader, MultcastAddr, 6);
	memcpy(MultcastHeader + 6, MAC, 6);
	MultcastHeader[12] = 0x88;
	MultcastHeader[13] = 0x8e;
	memcpy(BroadcastHeader, BroadcastAddr, 6);
	memcpy(BroadcastHeader + 6, MAC, 6);
	BroadcastHeader[12] = 0x88;
	BroadcastHeader[13] = 0x8e;
	memcpy(UnicastHeader, UnicastAddr, 6);
	memcpy(UnicastHeader + 6, MAC, 6);
	UnicastHeader[12] = 0x88;
	UnicastHeader[13] = 0x8e;
	memcpy(EthHeader + 6, MAC, 6);
	EthHeader[12] = 0x88;
	EthHeader[13] = 0x8e;
}
void printIfInfo() {
	LogWrite(INIT, INF, "Hostname: %s", HostName);
	LogWrite(INIT, INF, "IP: %s", inet_ntoa(local_ipaddr));
	LogWrite(INIT, INF, "DNS: %s", inet_ntoa(dns_ipaddr));
	LogWrite(INIT, INF, "UDP server: %s", inet_ntoa(udpserver_ipaddr));
	LogWrite(INIT, INF, "MAC: %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
		MAC[0], MAC[1], MAC[2], MAC[3], MAC[4], MAC[5]);
}
void loginToGetServerMAC(uint8_t recv_data[]) {
	fd_set fdR;
	struct timeval timeout = { AUTH_8021X_RECV_DELAY, 0 };
	struct timeval tmp_timeout = timeout;
	send_8021x_data_len = appendStartPkt(MultcastHeader);
	auth_8021x_Sender(send_8021x_data, send_8021x_data_len);
	LogWrite(DOT1X, INF, "%s", "Client: Multcast Start.");
	times = AUTH_8021X_RECV_TIMES;
	while (resev == 0) {
		FD_ZERO(&fdR);
		FD_SET(auth_8021x_sock, &fdR);
		tmp_timeout = timeout;
		switch (select(auth_8021x_sock + 1, &fdR, NULL, NULL, &tmp_timeout)) {
		case -1:
			LogWrite(DOT1X, ERROR, "Select socket for first packet failed: %s",
				strerror(errno));
			break;
		case 0:
			break;
		default:
			if (FD_ISSET(auth_8021x_sock, &fdR)) {
				if (auth_8021x_Receiver(recv_data)) {
					LogWrite(DOT1X, INF, "Received the first request.");
					resev = 1;
					times = AUTH_8021X_RECV_TIMES;
					memcpy(EthHeader, recv_data + 6, 6);
					if (auth_8021x_Handler(recv_data))
						exit(EXIT_FAILURE);
					return;
				}
				else {
					continue;
				}
			}
			break;
		}
		if (times <= 0) {
			LogWrite(DOT1X, ERROR, "Error! No Response");
			auth_8021x_Logoff();
			exit(EXIT_FAILURE);
		}
		times--;
		if (send_8021x_data[1] == 0xff) {
			send_8021x_data_len = appendStartPkt(MultcastHeader);
			auth_8021x_Sender(send_8021x_data, send_8021x_data_len);
			LogWrite(DOT1X, INF, "Client: Multcast Start.");
		}
		else if (send_8021x_data[1] == 0x80) {
			send_8021x_data_len = appendStartPkt(BroadcastHeader);
			auth_8021x_Sender(send_8021x_data, send_8021x_data_len);
			LogWrite(DOT1X, INF, "Client: Broadcast Start.");
		}
	}
}
int Authentication(int client) {
	struct timeval timeout = { AUTH_8021X_RECV_DELAY, 0 };
	struct timeval tmp_timeout = timeout;
	int ret = 0;
	fd_set fdR;
	uint8_t recv_8021x_buf[ETH_FRAME_LEN] = { 0 };
	if (auth_8021x_Init() != 0) {
		LogWrite(DOT1X, ERROR, "Unable to initialize 802.1x socket.");
		exit(EXIT_FAILURE);
	}
	initAuthenticationInfo();
	ret = auth_8021x_Logoff();
	if (client == LOGOFF) {
		close(auth_8021x_sock);
		return 0;
	}
	if (ret == 1) {
		sleep(2);
	}
	else if (ret < 0) {
		goto ERR1;
	}
	if ((ret = getIfIP(auth_8021x_sock)) < 0) {
		goto ERR1;
	}
	printIfInfo();
	if ((ret = auth_UDP_Init()) != 0) {
		LogWrite(DRCOM, ERROR, "Unable to initialize UDP socket.");
		goto ERR1;
	}
	loginToGetServerMAC(recv_8021x_buf);
	BaseHeartbeatTime = time(NULL);
	while (resev) {
		FD_ZERO(&fdR);
		FD_SET(auth_8021x_sock, &fdR);
		FD_SET(auth_udp_sock, &fdR);
		tmp_timeout = timeout;
		switch (select(auth_8021x_sock + auth_udp_sock + 1, &fdR, NULL, NULL,
			&tmp_timeout)) {
		case -1:
			LogWrite(ALL, ERROR, "select socket failed: %s", strerror(errno));
			ret = -1;
			resev = 0;
			break;
		case 0:
			break;
		default:
			if (FD_ISSET(auth_8021x_sock, &fdR)) {
				if (auth_8021x_Receiver(recv_8021x_buf)) {
					if ((ret = auth_8021x_Handler(recv_8021x_buf)) != 0) {
						resev = 0;
					}
				}
			}
			if (FD_ISSET(auth_udp_sock, &fdR)) {
				if (auth_UDP_Receiver(recv_udp_data)) {
					send_udp_data_len = Drcom_UDP_Handler(recv_udp_data);
					if (success_8021x && send_udp_data_len) {
						auth_UDP_Sender(send_udp_data, send_udp_data_len);
					}
				}
			}
			break;
		}
		if (success_8021x && isNeedHeartBeat) {
			if ((lastHBDone == 0)
				&& (time(NULL) - BaseHeartbeatTime > DRCOM_UDP_HEARTBEAT_TIMEOUT)) {
				LogWrite(DRCOM, ERROR, "Client: No response to last heartbeat.");
				ret = 1;
				break;
			}
			if (time(NULL) - BaseHeartbeatTime > DRCOM_UDP_HEARTBEAT_DELAY) {
				send_udp_data_len = Drcom_ALIVE_HEARTBEAT_TYPE_Setter(send_udp_data,
					recv_udp_data);
				LogWrite(DRCOM, INF, "Client: Send alive heartbeat.");
				if (auth_UDP_Sender(send_udp_data, send_udp_data_len) == 0) {
					ret = 1;
					break;
				}
				BaseHeartbeatTime = time(NULL);
				lastHBDone = 0;
			}
		}
	}
	success_8021x = 0;
	resev = 0;
	lastHBDone = 1;
	close(auth_udp_sock);
	auth_8021x_Logoff();
ERR1:
	close(auth_8021x_sock);
	return ret;
}
typedef enum { MISC_START_ALIVE = 0x01, MISC_RESPONSE_FOR_ALIVE = 0x02, MISC_INFO = 0x03, MISC_RESPONSE_INFO = 0x04, MISC_HEART_BEAT = 0x0b, MISC_RESPONSE_HEART_BEAT = 0x06 } DRCOM_Type;
typedef enum { MISC_HEART_BEAT_01_TYPE = 0x01, MISC_HEART_BEAT_02_TYPE = 0x02, MISC_HEART_BEAT_03_TYPE = 0x03, MISC_HEART_BEAT_04_TYPE = 0x04, MISC_FILE_TYPE = 0x06 } DRCOM_MISC_HEART_BEAT_Type;
int Drcom_UDP_Handler(uint8_t* recv_data) {
	int data_len = 0;
	if (recv_data[0] == 0x07) {
		switch ((DRCOM_Type)recv_data[4]) {
		case MISC_RESPONSE_FOR_ALIVE:
			sleep(1);
			isNeedHeartBeat = 0;
			BaseHeartbeatTime = time(NULL);
			lastHBDone = 1;
			data_len = Drcom_MISC_INFO_Setter(send_udp_data, recv_data);
			LogWrite(DRCOM, INF, "Server: MISC_RESPONSE_FOR_ALIVE. Send MISC_INFO.");
			break;
		case MISC_RESPONSE_INFO:
			memcpy(tailinfo, recv_data + 16, 16);
			encryptDrcomInfo(tailinfo);
			data_len = Drcom_MISC_HEART_BEAT_01_TYPE_Setter(send_udp_data, recv_data);
			isNeedHeartBeat = 1;
			LogWrite(DRCOM, INF, "Server: MISC_RESPONSE_INFO. Send MISC_HEART_BEAT_01.");
			break;
		case MISC_HEART_BEAT:
			switch ((DRCOM_MISC_HEART_BEAT_Type)recv_data[5]) {
			case MISC_FILE_TYPE:
				data_len = Drcom_MISC_HEART_BEAT_01_TYPE_Setter(send_udp_data, recv_data);
				LogWrite(DRCOM, INF, "Server: MISC_FILE_TYPE. Send MISC_HEART_BEAT_01.");
				break;
			case MISC_HEART_BEAT_02_TYPE:
				data_len = Drcom_MISC_HEART_BEAT_03_TYPE_Setter(send_udp_data, recv_data);
				LogWrite(DRCOM, INF, "Server: MISC_HEART_BEAT_02. Send MISC_HEART_BEAT_03.");
				break;
			case MISC_HEART_BEAT_04_TYPE:
				BaseHeartbeatTime = time(NULL);
				lastHBDone = 1;
				LogWrite(DRCOM, INF,
					"Server: MISC_HEART_BEAT_04. Waiting next heart beat cycle.");
				break;
			default:
				LogWrite(DRCOM, ERROR, "Server: Unexpected heart beat request (type:0x%02hhx)!",
					recv_data[5]);
				break;
			}
			break;
		case MISC_RESPONSE_HEART_BEAT:
			data_len = Drcom_MISC_HEART_BEAT_01_TYPE_Setter(send_udp_data, recv_data);
			LogWrite(DRCOM, INF,
				"Server: MISC_RESPONSE_HEART_BEAT. Send MISC_HEART_BEAT_01.");
			break;
		default:
			LogWrite(DRCOM, ERROR, "UDP Server: Unexpected request (type:0x%02hhx)!",
				recv_data[2]);
			break;
		}
	}
	if ((recv_data[0] == 0x4d) && (recv_data[1] == 0x38)) {
		LogWrite(DRCOM, INF, "%s%s", "Server: Server Information: ", recv_data + 4);
	}
	memset(recv_data, 0, ETH_FRAME_LEN);
	return data_len;
}

int auth_8021x_Handler(uint8_t recv_data[]) {
	uint16_t pkg_len = 0;
	const char* errstr;
	memcpy(&pkg_len, recv_data + 20, sizeof(pkg_len));
	pkg_len = htons(pkg_len);
	send_8021x_data_len = 0;
	if ((EAP_Code)recv_data[18] == REQUEST) {
		switch ((EAP_Type)recv_data[22]) {
		case IDENTITY:
			LogWrite(DOT1X, INF, "Server: Request Identity.");
			send_8021x_data_len = appendResponseIdentity(recv_data);
			LogWrite(DOT1X, INF, "Client: Response Identity.");
			break;
		case MD5:
			LogWrite(DOT1X, INF, "Server: Request MD5-Challenge.");
			send_8021x_data_len = appendResponseMD5(recv_data);
			LogWrite(DOT1X, INF, "Client: Response MD5-Challenge.");
			break;
		case NOTIFICATION:
			recv_data[23 + pkg_len - 5] = 0;
			if ((errstr = DrcomEAPErrParse((const char*)(recv_data + 23))) != NULL) {
				LogWrite(DOT1X, ERROR, "Server: Authentication failed: %s", errstr);
				return -1;
			}
			else {
				LogWrite(DOT1X, INF, "Server: Notification: %s", recv_data + 23);
			}
			break;
		case AVAILABLE:
			LogWrite(DOT1X, ERROR, "Unexpected request type (AVAILABLE). Pls report it.");
			break;
		case ALLOCATED_0x07:
			LogWrite(DOT1X, ERROR, "Unexpected request type (0x07). Pls report it.");
			break;
		case ALLOCATED_0x08:
			LogWrite(DOT1X, ERROR, "Unexpected request type (0x08). Pls report it.");
			break;
		default:
			LogWrite(DOT1X, ERROR, "Unexpected request type (0x%02hhx). Pls report it.",
				(EAP_Type)recv_data[22]);
			LogWrite(DOT1X, ERROR, "Exit.");
			return -1;
			break;
		}
	}
	else if ((EAP_Code)recv_data[18] == FAILURE) {
		success_8021x = 0;
		isNeedHeartBeat = 0;
		uint8_t errtype = recv_data[22];
		LogWrite(DOT1X, ERROR, "Server: Failure.");
		if (times > 0) {
			times--;
			sleep(AUTH_8021X_RECV_DELAY);
			return 1;
		}
		else {
			LogWrite(DOT1X, ERROR, "Reconnection failed. Server: errtype=0x%02hhx",
				errtype);
			exit(EXIT_FAILURE);
		}
	}
	else if ((EAP_Code)recv_data[18] == SUCCESS) {
		LogWrite(DOT1X, INF, "Server: Success.");
		times = AUTH_8021X_RECV_TIMES;
		success_8021x = 1;
		send_udp_data_len = Drcom_MISC_START_ALIVE_Setter(send_udp_data,
			recv_data);
		sleep(AUTH_8021X_RECV_DELAY);
		if (OnlineHookCmd) {
			system(OnlineHookCmd);
		}
		isNeedHeartBeat = 1;
		BaseHeartbeatTime = time(NULL);
		lastHBDone = 0;
		auth_UDP_Sender(send_udp_data, send_udp_data_len);
	}
	if (send_8021x_data_len > 0) {
		auth_8021x_Sender(send_8021x_data, send_8021x_data_len);
	}
	return 0;
}
