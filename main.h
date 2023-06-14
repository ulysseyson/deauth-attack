#include "dot11.h"

typedef struct _deauth_packet{
    radiotap_header_t radiotap;
    beacon_frame_t dot11;
    int reason_code;
} __attribute__((__packed__)) deauth_packet_t;