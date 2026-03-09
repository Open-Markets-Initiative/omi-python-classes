from omipy.iex.equities.deepplus.v1_0_1 import Iex


# Parse pcap file
for packet in Iex.packets("path/to/file.pcap"):
    print(f"Packet: {packet._name}, Messages: {len(packet.messages)}")

    for message in packet.messages:
        print(f"  {message.message_data._name}")
