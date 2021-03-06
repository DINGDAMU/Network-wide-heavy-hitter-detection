/* Copyright 2013-present Barefoot Networks, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

parser start {
    return select(current(0, 64)) {
            0 : parse_cpu_header;       // Go to parser parse_cpu_header
            default: parse_ethernet;    // Go to parser parse_ethernet
                        }
                        }

#define ETHERTYPE_IPV4 0x0800
header cpu_header_t cpu_header;
header ethernet_t ethernet;

parser parse_cpu_header {
    extract(cpu_header);
        return parse_ethernet;
        }

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
        default: ingress;
    }
}

header ipv4_t ipv4;

#define TCP_PROTO 0x06
#define UDP_PROTO 0x11

parser parse_ipv4 {
    extract(ipv4);
    return select(latest.protocol) {
        TCP_PROTO : parse_tcp;
        UDP_PROTO : parse_udp;
        default: ingress;
    }
}

header tcp_t tcp;

parser parse_tcp {
    extract(tcp);
    return ingress;
}
header udp_t udp;

parser parse_udp {
    extract(udp);
    return ingress;
}
