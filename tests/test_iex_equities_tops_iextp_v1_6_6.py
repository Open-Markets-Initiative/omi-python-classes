from omipy.iex.equities.tops.v1_6_6 import Iex


def test_quoteupdatemessage():
    packets = list(Iex.packets("omi-data-packets/Iex/Tops.IexTp.v1.6/QuoteUpdateMessage.pcap"))
    assert len(packets) > 0
    assert all(p.valid for p in packets)


