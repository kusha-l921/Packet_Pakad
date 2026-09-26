from scapy.all import IP, UDP, Raw, wrpcap
import struct


def ikev2_header(
    spi_i,
    spi_r,
    next_payload,
    exchange_type,
    message_id,
    length
):
    return (
        spi_i
        + spi_r
        + bytes([next_payload])
        + bytes([0x20])
        + bytes([exchange_type])
        + bytes([0x08])
        + struct.pack("!I", message_id)
        + struct.pack("!I", length)
    )


def ikev2_payload(next_payload, payload_data):

    length = 4 + len(payload_data)

    return (
        bytes([next_payload])
        + bytes([0])
        + struct.pack("!H", length)
        + payload_data
    )


# ---------------------------------------------------------
# IKEv2 identifiers
# ---------------------------------------------------------

spi_i = bytes.fromhex(
    "1122334455667788"
)

spi_r = bytes.fromhex(
    "8877665544332211"
)


# ---------------------------------------------------------
# Encryption Transform
#
# Type 1 = Encryption
# ID 20 = AES-256
# ---------------------------------------------------------

encryption_transform = (
    bytes([3])
    + bytes([0])
    + struct.pack("!H", 8)
    + bytes([1])
    + bytes([0])
    + struct.pack("!H", 20)
)


# ---------------------------------------------------------
# Integrity Transform
#
# Type 3 = Integrity
# ID 12 = HMAC-SHA2-256-128
# ---------------------------------------------------------

integrity_transform = (
    bytes([3])
    + bytes([0])
    + struct.pack("!H", 8)
    + bytes([3])
    + bytes([0])
    + struct.pack("!H", 12)
)


# ---------------------------------------------------------
# DH Transform
#
# Type 4 = Diffie-Hellman
# ID 14 = DH Group 14
# ---------------------------------------------------------

dh_transform = (
    bytes([3])
    + bytes([0])
    + struct.pack("!H", 8)
    + bytes([4])
    + bytes([0])
    + struct.pack("!H", 14)
)


# ---------------------------------------------------------
# Combine transforms
# ---------------------------------------------------------

transforms = (
    encryption_transform
    + integrity_transform
    + dh_transform
)


# ---------------------------------------------------------
# Proposal
# ---------------------------------------------------------

proposal_length = (
    8
    + len(transforms)
)

proposal = (
    bytes([0])
    + bytes([0])
    + struct.pack(
        "!H",
        proposal_length
    )
    + bytes([1])
    + bytes([1])
    + bytes([3])
    + bytes([0])
    + transforms
)


# ---------------------------------------------------------
# Security Association payload
#
# Next payload = KE (34)
# ---------------------------------------------------------

sa_payload = ikev2_payload(
    34,
    proposal
)


# ---------------------------------------------------------
# Key Exchange payload
#
# Group 14
# ---------------------------------------------------------

ke_data = (
    struct.pack("!H", 14)
    + struct.pack("!H", 0)
    + b"\x00" * 32
)

ke_payload = ikev2_payload(
    0,
    ke_data
)


# ---------------------------------------------------------
# Complete IKE_SA_INIT payload
# ---------------------------------------------------------

payload = (
    sa_payload
    + ke_payload
)


# ---------------------------------------------------------
# IKEv2 Header
#
# Exchange type 34 = IKE_SA_INIT
# ---------------------------------------------------------

header_length = (
    28
    + len(payload)
)

header = ikev2_header(
    spi_i,
    spi_r,
    33,
    34,
    0,
    header_length
)


# ---------------------------------------------------------
# Complete IKEv2 message
# ---------------------------------------------------------

ike_packet = (
    header
    + payload
)


# ---------------------------------------------------------
# Build Ethernet-independent IP packet
# ---------------------------------------------------------

packet = (
    IP(
        src="10.0.0.1",
        dst="10.0.0.2"
    )
    /
    UDP(
        sport=500,
        dport=500
    )
    /
    Raw(
        load=ike_packet
    )
)


# ---------------------------------------------------------
# Save PCAP
# ---------------------------------------------------------

output_file = (
    "data/uploads/ikev2_sa_test.pcap"
)

wrpcap(
    output_file,
    [packet]
)


print()
print("=" * 60)
print("TUNNELGUARD IKEv2 SA TEST")
print("=" * 60)
print()
print("PCAP created successfully")
print()
print("File:")
print(output_file)
print()
print("Encryption : AES-256")
print("Integrity  : HMAC-SHA256")
print("DH Group   : 14")
print()
print("Packet size:", len(ike_packet))
print()
print("=" * 60)
