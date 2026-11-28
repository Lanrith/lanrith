/* Package acceptance. Exercise the compiled IPv4-to-IPv6 UDP conversion
 * directly, including bounds that an ordinary socket cannot represent. */
#include "nat64.c"
#include <assert.h>

static struct config settings;
struct config *gcfg = &settings;

static unsigned word(const uint8_t *bytes)
{
	return (unsigned)bytes[0] << 8 | bytes[1];
}

/* Sum RFC 8200 pseudo-header and UDP bytes in wire order independently
 * of the native-word arithmetic used by the translator. */
static uint16_t reference(const struct ip6 *header, const uint8_t *udp, unsigned length)
{
	unsigned sum = length + 17;
	for (unsigned i = 0; i < 16; i += 2) {
		sum += word(header->src.s6_addr + i);
		sum += word(header->dest.s6_addr + i);
	}
	for (unsigned i = 0; i < length; i += 2)
		sum += (unsigned)udp[i] << 8 | (i + 1 < length ? udp[i + 1] : 0);
	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);
	return (uint16_t)~sum;
}

int main(void)
{
	struct ip6 header = {0};
	struct ip4 original = {0};
	_Alignas(4) uint8_t udp[20] = {0x1f, 0x90, 0x1f, 0x91, 0, 0, 0, 0};
	struct pkt packet = {.data = udp, .data_proto = 17, .ip4 = &original};

	assert(inet_pton(AF_INET6, "2001:db8:1::12", &header.src) == 1);
	assert(inet_pton(AF_INET6, "2001:db8:2::34", &header.dest) == 1);
	settings.udp_cksum_mode = UDP_CKSUM_CALC;
	for (unsigned length = 8; length <= sizeof(udp); length++) {
		memset(udp + 8, 'x', sizeof(udp) - 8);
		udp[5] = length;
		udp[6] = udp[7] = 0;
		uint16_t expected = reference(&header, udp, length);
		packet.data_len = sizeof(udp); /* Some inputs have padding. */
		assert(xlate_payload_4to6(&packet, &header, 0) == ERROR_NONE);
		assert(word(udp + 6) == (expected ? expected : UINT16_MAX));
		assert(reference(&header, udp, length) == 0);
	}

	udp[5] = packet.data_len = 10;
	memset(udp + 6, 0, 4);
	uint16_t balance = reference(&header, udp, 10);
	udp[8] = balance >> 8;
	udp[9] = balance & 0xff;
	assert(reference(&header, udp, 10) == 0);
	assert(xlate_payload_4to6(&packet, &header, 0) == ERROR_NONE);
	assert(word(udp + 6) == UINT16_MAX);

	udp[6] = udp[7] = 0;
	packet.data_len = 8;
	assert(xlate_payload_4to6(&packet, &header, 0) == ERROR_DROP);
	assert(word(udp + 6) == 0 && incomplete_udp_drops == 1);
	udp[5] = 7;
	assert(xlate_payload_4to6(&packet, &header, 0) == ERROR_DROP);
	udp[5] = 8;
	original.flags_offset = htons(IP4_F_MF);
	assert(xlate_payload_4to6(&packet, &header, 0) == ERROR_DROP);
	assert(word(udp + 6) == 0 && incomplete_udp_drops == 3);

	original.flags_offset = 0;
	settings.udp_cksum_mode = UDP_CKSUM_DROP;
	assert(xlate_payload_4to6(&packet, &header, 0) == ERROR_DROP);
	settings.udp_cksum_mode = UDP_CKSUM_FWD;
	assert(xlate_payload_4to6(&packet, &header, 0) == ERROR_NONE);
	assert(word(udp + 6) == 0 && incomplete_udp_drops == 3);
	puts("TAYGA UDP checksum acceptance passed");
}
