#include "drcom.h"
#include "functions.h"
#include "info.h"
extern struct in_addr local_ipaddr;
extern uint8_t MAC[6];
typedef enum { REQUEST = 1, RESPONSE = 2, SUCCESS = 3, FAILURE = 4, H3CDATA = 10 } EAP_Code;
typedef enum { IDENTITY = 1, NOTIFICATION = 2, MD5 = 4, AVAILABLE = 20, ALLOCATED = 7 } EAP_Type;
typedef enum { MISC_0800 = 0x08, ALIVE_FILE = 0x10, MISC_3000 = 0x30, MISC_2800 = 0x28 } DRCOM_Type;
static uint8_t crc_md5_info[16];
static int drcom_package_id = 0;
char drcom_misc1_flux[4];
char drcom_misc3_flux[4];
uint8_t timeNotAllowed = 0;
uint8_t tailinfo[16];
uint32_t drcom_crc32(uint8_t* data, int data_len) {
	uint32_t ret = 0;
	int i;
	for (i = 0; i < data_len; i += 4) {
		ret ^= *(unsigned int*)(data + i);
		ret &= 0xFFFFFFFF;
	}
	ret = htole32(ret);
	ret = (ret * 19680126) & 0xFFFFFFFF;
	ret = htole32(ret);
	return ret;
}
void encryptDrcomInfo(unsigned char* info) {
	int i;
	unsigned char* chartmp = NULL;
	chartmp = (unsigned char*)malloc(16);
	for (i = 0; i < 16; i++) {
		chartmp[i] = (unsigned char)((info[i] << (i & 0x07))
			+ (info[i] >> (8 - (i & 0x07))));
	}
	memcpy(info, chartmp, 16);
	free(chartmp);
}
size_t AppendDrcomStartPkt(uint8_t* EthHeader, uint8_t* Packet) {
	size_t packetlen = 0;
	LogWrite(DRCOM, DEBUG, "Preparing Start packet...");
	memset(Packet, 0x00, 97);
	memcpy(Packet, EthHeader, 14);
	Packet[14] = 0x01;
	Packet[15] = 0x01;
	Packet[16] = 0x00;
	Packet[17] = 0x00;
	packetlen = 96;
	return packetlen;
}
size_t AppendDrcomResponseIdentity(const uint8_t* request, uint8_t* EthHeader,
	const char* UserName, uint8_t* Packet) {
	size_t packetlen = 0;
	size_t userlen = strlen(UserName);
	LogWrite(DRCOM, DEBUG, "Preparing Dr.com identity...");
	memset(Packet, 0x00, 97);
	uint16_t eaplen;
	memcpy(Packet, EthHeader, 14);
	Packet[14] = 0x1;
	Packet[15] = 0x0;
	Packet[18] = RESPONSE;
	Packet[19] = request[19];
	Packet[22] = IDENTITY;
	packetlen = 23;
	memcpy(Packet + packetlen, UserName, userlen);
	packetlen += userlen;
	Packet[packetlen++] = 0x0;
	Packet[packetlen++] = 0x44;
	Packet[packetlen++] = 0x61;
	Packet[packetlen++] = 0x0;
	Packet[packetlen++] = 0x0;
	memcpy(Packet + packetlen, (char*)(&local_ipaddr.s_addr), 4);
	packetlen += 4;
	if (packetlen < 96) {
		packetlen = 96;
	}
	eaplen = htons(userlen + 14);
	memcpy(Packet + 16, &eaplen, sizeof(eaplen));
	eaplen = htons(userlen + 14);
	memcpy(Packet + 20, &eaplen, sizeof(eaplen));
	return packetlen;
}
size_t AppendDrcomResponseMD5(const uint8_t* request, uint8_t* EthHeader,
	const char* UserName, const char* Password, uint8_t* Packet) {
	size_t packetlen = 0;
	size_t userlen = strlen(UserName);
	uint16_t eaplen = 0;
	LogWrite(DRCOM, DEBUG, "Preparing Dr.com MD5 response...");
	memset(Packet, 0x00, 97);
	memcpy(Packet, EthHeader, 14);
	Packet[14] = 0x1;
	Packet[15] = 0x0;
	Packet[18] = RESPONSE;
	Packet[19] = request[19];
	Packet[22] = MD5;
	Packet[23] = 0x10;
	packetlen = 24;
	FillMD5Area(Packet + packetlen, request[19], Password, request + 24);
	memcpy(crc_md5_info, Packet + packetlen, 16);
	packetlen += 16;
	memcpy(Packet + packetlen, UserName, userlen);
	packetlen += userlen;
	Packet[packetlen++] = 0x0;
	Packet[packetlen++] = 0x44;
	Packet[packetlen++] = 0x61;
	Packet[packetlen++] = 0x2a;
	Packet[packetlen++] = 0x0;
	memcpy(Packet + packetlen, (char*)(&local_ipaddr.s_addr), 4);
	packetlen += 4;
	eaplen = htons(userlen + 31);
	memcpy(Packet + 16, &eaplen, sizeof(eaplen));
	eaplen = htons(userlen + 31);
	memcpy(Packet + 20, &eaplen, sizeof(eaplen));
	if (packetlen < 96) {
		packetlen = 96;
	}
	return packetlen;
}
size_t AppendDrcomLogoffPkt(uint8_t* EthHeader, uint8_t* Packet) {
	size_t packetlen = 0;
	memset(Packet, 0xa5, 97);
	memcpy(Packet, EthHeader, 14);
	Packet[14] = 0x01;
	Packet[15] = 0x02;
	Packet[16] = 0x00;
	Packet[17] = 0x00;
	packetlen = 96;
	return packetlen;
}
const char* DrcomEAPErrParse(const char* str) {
	int errcode;
	if (!strncmp("userid error", str, 12)) {
		sscanf(str, "userid error%d", &errcode);
		switch (errcode) {
		case 1:
			return "Account does not exist.";
		case 2:
		case 3:
			return "Username or password invalid.";
		case 4:
			return "This account might be expended.";
		default:
			return str;
		}
	}
	else if (!strncmp("Authentication Fail", str, 19)) {
		sscanf(str, "Authentication Fail ErrCode=%d", &errcode);
		switch (errcode) {
		case 0:
			return "Username or password invalid.";
		case 5:
			return "This account is suspended.";
		case 9:
			return "This account might be expended.";
		case 11:
			return "You are not allowed to perform a radius authentication.";
		case 16:
			timeNotAllowed = 1;
			return "You are not allowed to access the internet now.";
		case 30:
		case 63:
			return "No more time available for this account.";
		default:
			return str;
		}
	}
	else if (!strncmp("AdminReset", str, 10)) {
		return str;
	}
	else if (strstr(str, "Mac, IP, NASip, PORT")) {
		return "You are not allowed to login using current IP/MAC address.";
	}
	else if (strstr(str, "flowover")) {
		return "Data usage has reached the limit.";
	}
	else if (strstr(str, "In use")) {
		return "This account is in use.";
	}
	return NULL;
}
int Drcom_MISC_START_ALIVE_Setter(uint8_t* send_data, uint8_t* recv_data) {
	int packetlen = 0;
	send_data[packetlen++] = 0x07;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x08;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x01;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x00;
	return packetlen;
}
int Drcom_MISC_INFO_Setter(uint8_t* send_data, uint8_t* recv_data) {
	int packetlen = 0;
	send_data[packetlen++] = 0x07;
	send_data[packetlen++] = 0x01;
	send_data[packetlen++] = 0xf4;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x03;
	send_data[packetlen++] = strlen(UserName);
	memcpy(send_data + packetlen, MAC, 6);
	packetlen += 6;
	memcpy(send_data + packetlen, (char*)(&local_ipaddr.s_addr), 4);
	packetlen += 4;
	send_data[packetlen++] = 0x02;
	send_data[packetlen++] = 0x22;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x2a;
	memcpy(send_data + packetlen, recv_data + 8, 4);
	packetlen += 4;
	send_data[packetlen++] = 0xc7;
	send_data[packetlen++] = 0x2f;
	send_data[packetlen++] = 0x31;
	send_data[packetlen++] = 0x01;
	send_data[packetlen++] = 0x7e;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x00;
	memcpy(send_data + packetlen, UserName, strlen(UserName));
	packetlen += strlen(UserName);
	memcpy(send_data + packetlen, HostName, 32 - strlen(UserName));
	packetlen += 32 - strlen(UserName);
	memset(send_data + packetlen, 0x00, 32);
	packetlen += 12;
	memcpy(send_data + packetlen, (char*) & (dns_ipaddr.s_addr), 4);
	packetlen += 4;
	packetlen += 16;
	send_data[packetlen++] = 0x94;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x06;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x02;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0xf0;
	send_data[packetlen++] = 0x23;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x02;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x00;
	memset(send_data + packetlen, 0x00, 64);
	memcpy(send_data + packetlen, Version, Version_len);
	packetlen += 64;
	memset(send_data + packetlen, 0x00, 68);
	memcpy(send_data + packetlen, Hash, strlen(Hash));
	packetlen += 64;
	if (packetlen % 4 != 0) {
		packetlen = packetlen + 4 - (packetlen % 4);
	}
	send_data[2] = 0xFF & packetlen;
	send_data[3] = 0xFF & (packetlen >> 8);
	uint32_t crc = drcom_crc32(send_data, packetlen);
	memcpy(send_data + 24, &crc, 4);
	memcpy(crc_md5_info, &crc, 4);
	send_data[28] = 0x00;
	return packetlen;
}
int Drcom_MISC_HEART_BEAT_01_TYPE_Setter(uint8_t* send_data,
	uint8_t* recv_data) {
	int packetlen = 0;
	memset(send_data, 0, 40);
	send_data[packetlen++] = 0x07;
	send_data[packetlen++] = drcom_package_id++;
	send_data[packetlen++] = 0x28;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x0b;
	send_data[packetlen++] = 0x01;
	send_data[packetlen++] = 0xdc;
	send_data[packetlen++] = 0x02;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x00;
	memcpy(send_data + 16, drcom_misc1_flux, 4);
	packetlen = 40;
	return packetlen;
}
int Drcom_MISC_HEART_BEAT_03_TYPE_Setter(uint8_t* send_data,
	uint8_t* recv_data) {
	memcpy(&drcom_misc3_flux, recv_data + 16, 4);
	memset(send_data, 0, 40);
	int packetlen = 0;
	send_data[packetlen++] = 0x07;
	send_data[packetlen++] = drcom_package_id++;
	send_data[packetlen++] = 0x28;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x0b;
	send_data[packetlen++] = 0x03;
	send_data[packetlen++] = 0xdc;
	send_data[packetlen++] = 0x02;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x00;
	memcpy(send_data + 16, drcom_misc3_flux, 4);
	memcpy(send_data + 28, (char*)(&local_ipaddr.s_addr), 4);
	packetlen = 40;
	return packetlen;
}
int Drcom_ALIVE_HEARTBEAT_TYPE_Setter(uint8_t* send_data, uint8_t* recv_data) {
	int packetlen = 0;
	send_data[packetlen++] = 0xff;
	memcpy(send_data + packetlen, crc_md5_info, 16);
	packetlen += 16;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x00;
	send_data[packetlen++] = 0x00;
	memcpy(send_data + packetlen, tailinfo, 16);
	packetlen += 16;
	time_t timeinfo = time(NULL);
	send_data[packetlen++] = 0xff & timeinfo;
	send_data[packetlen++] = 0xff & (timeinfo >> 8);
	return packetlen;
}
