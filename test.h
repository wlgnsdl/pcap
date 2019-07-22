#ifndef TEST_H
#define TEST_H
#include <stdint.h>

#define ETH_ALEN 6

struct ether_header
{
  uint8_t  ether_dhost[6];	/* destination eth addr	*/
  uint8_t  ether_shost[6];	/* source ether addr	*/
  uint16_t ether_type;		        /* packet type ID field	*/
};

#endif // TEST_H
