// Link with the selected Debian libavahi-core and its matching source headers.
// The send functions below count attempts without opening any network sockets.
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "avahi-core/internal.h"
#include "avahi-core/socket.h"

static unsigned attempts[2][2];

int avahi_send_dns_packet_ipv4(int fd, AvahiIfIndex link, AvahiDnsPacket *packet,
        const AvahiIPv4Address *src, const AvahiIPv4Address *dst, uint16_t port) {
    attempts[link][0]++;
    return 0;
}

int avahi_send_dns_packet_ipv6(int fd, AvahiIfIndex link, AvahiDnsPacket *packet,
        const AvahiIPv6Address *src, const AvahiIPv6Address *dst, uint16_t port) {
    attempts[link][1]++;
    return 0;
}

int main(int argc, char **argv) {
    assert(argc == 3);
    AvahiServer server = {0};
    server.config.ratelimit_interval = atoi(argv[1]);
    server.config.ratelimit_burst = atoi(argv[2]);
    assert(server.config.ratelimit_interval == 1000000 && server.config.ratelimit_burst == 1000);
    AvahiInterfaceMonitor monitor = {.server = &server};
    AvahiHwInterface hw[2] = {{.index = 0}, {.index = 1}};
    AvahiInterface iface = {.monitor = &monitor, .announcing = 1};
    AvahiDnsPacket packet = {0};

    for (int link = 0; link < 2; link++) {
        iface.hardware = &hw[link];
        for (unsigned i = 0; i < server.config.ratelimit_burst + 5; i++) {
            iface.protocol = i % 2 == 0 ? AVAHI_PROTO_INET : AVAHI_PROTO_INET6;
            avahi_interface_send_packet(&iface, &packet);
        }
        assert(attempts[link][0] == 501 && attempts[link][1] == 500);
    }
    // Move only the first hardware interface's window into the past.
    hw[0].ratelimit_begin.tv_sec -= 2;
    for (int link = 0; link < 2; link++) {
        iface.hardware = &hw[link];
        iface.protocol = AVAHI_PROTO_INET6;
        avahi_interface_send_packet(&iface, &packet);
        assert(attempts[link][1] == (link == 0 ? 501 : 500));
    }
    puts("Two independent link windows shared across IPv4/IPv6; burst + 1 and reset passed.");
}
