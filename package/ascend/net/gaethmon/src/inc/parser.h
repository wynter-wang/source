#ifndef _PARSER_H_
#define _PARSER_H_

struct packet_info;

int parse_packet(unsigned char *buf, int len, struct packet_info *p);

#endif
