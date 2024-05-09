#!/bin/bash

detect_dos() {
    interface="enxa842a1462190"

    tcpdump -i $interface -n -l | \

    awk -v threshold=1000 '
        function djb2(s) {
            hash = 5381;
            for (i = 1; i <= length(s); i++) {
                c = substr(s, i, 1);
                code = sprintf("%d", 0 + c); # Get ASCII value of character
                hash = (hash * 33) + code;
            }
            return hash;
        }
        BEGIN {
            delete packets;
        }
        {
            source_ip = $3;
            dest_port = $7;

            packet_hash = djb2(source_ip ":" dest_port);

            if (packet_hash in packets) {
                packets[packet_hash]++;
            } else {
                packets[packet_hash] = 1;
            }

            if (packets[packet_hash] >= threshold) {
                print "Potential DoS attack detected !!";
                print "Source IP:", source_ip, "Destination Port:", dest_port;
                print "Number of packets:", packets[packet_hash];
            }
        }
    '
}

detect_dos
