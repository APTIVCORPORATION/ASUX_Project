#include "stdint.h"


const size_t UDP_PAYLOAD_SIZE = 32000;

#pragma pack(push,1)
	struct udphdr {
		/** Source port */
		uint16_t portSrc;
		/** Destination port */
		uint16_t portDst;
		/** Length of header and payload in bytes */
		uint16_t length;
		/**  Error-checking of the header and data */
		uint16_t headerChecksum;
	};
#pragma pack(pop)


struct UDPRecord_Header
{
	udphdr 			  header;
	unsigned char    payload[UDP_PAYLOAD_SIZE];

};