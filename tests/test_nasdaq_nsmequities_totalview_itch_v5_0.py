from omipy.nasdaq.nsmequities.totalview.v5_0 import Nasdaq


def test_addordernompidattributionmessage():
    packets = list(Nasdaq.packets("omi-data-packets/Nasdaq/Nasdaq.Equities.TotalView.Itch.v5.0/AddOrderNoMpidAttributionMessage.pcap"))
    assert len(packets) > 0
    assert all(p.valid for p in packets)


def test_orderdeletemessage():
    packets = list(Nasdaq.packets("omi-data-packets/Nasdaq/Nasdaq.Equities.TotalView.Itch.v5.0/OrderDeleteMessage.pcap"))
    assert len(packets) > 0
    assert all(p.valid for p in packets)


