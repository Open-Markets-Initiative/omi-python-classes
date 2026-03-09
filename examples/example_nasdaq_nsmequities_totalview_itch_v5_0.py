from omipy.nasdaq.nsmequities.totalview.v5_0 import Nasdaq


# Parse pcap file
for packet in Nasdaq.packets("path/to/file.pcap"):
    print(f"Packet: {packet._name}, Messages: {len(packet.messages)}")

    for message in packet.messages:
        print(f"  {message.message_data._name}")
