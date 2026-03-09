from omipy.iex.equities.tops.v1_6_6 import Iex


def test_quoteupdatemessage():
    packets = list(Iex.packets("omi-data-packets/Iex/Tops.v1.6.6/QuoteUpdateMessage.Q.pcap"))
    assert len(packets) > 0
    assert all(p.valid for p in packets)


def test_systemeventmessage():
    packets = list(Iex.packets("omi-data-packets/Iex/Tops.v1.6.6/SystemEventMessage.S.pcap"))
    assert len(packets) > 0
    assert all(p.valid for p in packets)


def test_tradereport():
    packets = list(Iex.packets("omi-data-packets/Iex/Tops.v1.6.6/TradeReport.T.pcap"))
    assert len(packets) > 0
    assert all(p.valid for p in packets)


