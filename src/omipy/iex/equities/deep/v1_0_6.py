import os
from pathlib import Path
from enum import Enum, Flag, auto
from typing import Generator

from pcapkit import extract
from pcapkit.protocols.transport import UDP, TCP


class _Unknown:
    __slots__ = ('_error', '_length', 'valid')

    def __init__(self, message_type):
        self._error = f"Unknown message type: {message_type}"
        self._length = 0
        self.valid = False
class Iex:
    _name: str = "IexIexTpDeep"
    _version: str = "1.0.6"

    @staticmethod
    def frames(path: str | Path) -> Generator[bytes, None, None]:

        if not os.path.exists(path):
            raise FileNotFoundError(path)

        if not os.path.isfile(path):
            raise ValueError(f"Can only operate on files: {path}")

        capture = extract(path, nofile=True)

        for frame in capture.frame:
            udp = frame[UDP].payload

            yield udp

    @staticmethod
    def packets(path: str | Path):
        for frame in Iex.frames(path):

            packet = Packet(frame.data)

            if packet.valid:
                yield packet

    @staticmethod
    def messages(path: str | Path):
        for packet in Iex.packets(path):
            for message in packet.messages:
                yield message


### Types ###

class AdjustedPocPrice:
    """Corporate action adjusted previous official closing price"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value', 'precision')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Adjusted Poc Price"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None
        self.precision = 4

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = int.from_bytes(self.raw, byteorder="little", signed=True)
            self.value = self.value / 10**self.precision
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 8

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return str(self.value)


class AuctionBookClearingPrice:
    """Clearing price using orders on the Auction Book"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value', 'precision')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Auction Book Clearing Price"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None
        self.precision = 4

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = int.from_bytes(self.raw, byteorder="little", signed=True)
            self.value = self.value / 10**self.precision
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 8

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return str(self.value)


class AuctionType:
    """Auction type identifier"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Auction Type"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = self.raw.decode("ascii")
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 1

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return self.value


class ChannelId:
    """Identifies the stream of bytes sequenced messages"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Channel Id"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = int.from_bytes(self.raw, byteorder="little", signed=False)
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 4

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return str(self.value)


class CollarReferencePrice:
    """Reference priced used for the auction collar, if any"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value', 'precision')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Collar Reference Price"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None
        self.precision = 4

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = int.from_bytes(self.raw, byteorder="little", signed=True)
            self.value = self.value / 10**self.precision
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 8

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return str(self.value)


class Detail:
    """Detail of the Reg. SHO short sale price test restriction status"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Detail"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = self.raw.decode("ascii")
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 1

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return self.value


class Etp:
    """Symbol is an ETP"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Etp"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = self.raw.decode("ascii")
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 1

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return self.value


class EventFlags:
    """Identifies event processing by the System"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Event Flags"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = int.from_bytes(self.raw, byteorder="little", signed=False)
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 1

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return str(self.value)


class ExtendedHours:
    """Extended Hours Trade"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Extended Hours"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = self.raw.decode("ascii")
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 1

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return self.value


class ExtensionNumber:
    """Number of extensions an auction received"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Extension Number"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = self.raw.decode("ascii")
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 1

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return self.value


class FirstMessageSequenceNumber:
    """Sequence of the first message in the segment"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "First Message Sequence Number"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = int.from_bytes(self.raw, byteorder="little", signed=False)
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 8

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return str(self.value)


class ImbalanceShares:
    """Number of unpaired shares at the Reference Price using orders on the Auction Book"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Imbalance Shares"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = int.from_bytes(self.raw, byteorder="little", signed=False)
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 4

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return str(self.value)


class ImbalanceSide:
    """Side of the unpaired shares at the Reference Price using orders on the Auction Book"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Imbalance Side"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = self.raw.decode("ascii")
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 1

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return self.value


class IndicativeClearingPrice:
    """Clearing price using Eligible Auction Orders"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value', 'precision')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Indicative Clearing Price"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None
        self.precision = 4

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = int.from_bytes(self.raw, byteorder="little", signed=True)
            self.value = self.value / 10**self.precision
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 8

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return str(self.value)


class IntermarketSweep:
    """Intermarket Sweep Order"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Intermarket Sweep"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = self.raw.decode("ascii")
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 1

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return self.value


class LowerAuctionCollar:
    """Lower threshold price of the auction collar, if any"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value', 'precision')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Lower Auction Collar"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None
        self.precision = 4

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = int.from_bytes(self.raw, byteorder="little", signed=True)
            self.value = self.value / 10**self.precision
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 8

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return str(self.value)


class LuldTier:
    """Indicates which Limit Up-Limit Down price band calculation parameter is to be used"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Luld Tier"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = int.from_bytes(self.raw, byteorder="little", signed=False)
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 1

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return str(self.value)


class MessageCount:
    """Number of messages in the payload"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Message Count"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = int.from_bytes(self.raw, byteorder="little", signed=False)
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 2

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return str(self.value)


class MessageLength:
    """Length of the message"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Message Length"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = int.from_bytes(self.raw, byteorder="little", signed=False)
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 2

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return str(self.value)


class MessageProtocolId:
    """Unique identifier of the higher layer protocol"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Message Protocol Id"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = int.from_bytes(self.raw, byteorder="little", signed=False)
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 2

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return str(self.value)


class MessageType:
    """Code identifying this message type"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Message Type"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = self.raw.decode("ascii")
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 1

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return self.value


class OddLot:
    """Odd Lot"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Odd Lot"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = self.raw.decode("ascii")
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 1

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return self.value


class OfficialPrice:
    """Official opening or closing price, as specified"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value', 'precision')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Official Price"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None
        self.precision = 4

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = int.from_bytes(self.raw, byteorder="little", signed=True)
            self.value = self.value / 10**self.precision
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 8

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return str(self.value)


class OperationalHaltStatus:
    """Operational halt status identifier"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Operational Halt Status"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = self.raw.decode("ascii")
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 1

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return self.value


class PairedShares:
    """Number of shares paired at the Reference Price using orders on the Auction Book"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Paired Shares"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = int.from_bytes(self.raw, byteorder="little", signed=False)
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 4

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return str(self.value)


class PayloadLength:
    """Byte length of the payload"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Payload Length"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = int.from_bytes(self.raw, byteorder="little", signed=False)
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 2

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return str(self.value)


class Price:
    """Price level to add/update in the IEX Order Book"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value', 'precision')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Price"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None
        self.precision = 4

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = int.from_bytes(self.raw, byteorder="little", signed=True)
            self.value = self.value / 10**self.precision
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 8

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return str(self.value)


class PriceType:
    """Price type identifier"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Price Type"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = self.raw.decode("ascii")
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 1

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return self.value


class Reason:
    """Reason for the trading status change"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Reason"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = self.raw.decode("ascii")
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 4

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return self.value


class ReferencePrice:
    """Clearing price at or within the Reference Price Range using orders on the Auction Book"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value', 'precision')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Reference Price"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None
        self.precision = 4

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = int.from_bytes(self.raw, byteorder="little", signed=True)
            self.value = self.value / 10**self.precision
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 8

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return str(self.value)


class Reserved:
    """Reserved byte"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Reserved"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = self.raw.decode("ascii")
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 1

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return self.value


class RoundLotSize:
    """Number of shares that represent a round lot"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Round Lot Size"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = int.from_bytes(self.raw, byteorder="little", signed=False)
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 4

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return str(self.value)


class ScheduledAuctionTime:
    """Projected time of the auction match"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Scheduled Auction Time"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = int.from_bytes(self.raw, byteorder="little", signed=False)
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 4

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return str(self.value)


class SecurityEvent:
    """Security event identifier"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Security Event"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = self.raw.decode("ascii")
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 1

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return self.value


class SendTime:
    """Send time of segment"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Send Time"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = int.from_bytes(self.raw, byteorder="little", signed=False)
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 8

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return str(self.value)


class SessionId:
    """Identifies the session"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Session Id"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = int.from_bytes(self.raw, byteorder="little", signed=False)
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 4

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return str(self.value)


class ShortSalePriceTestStatus:
    """Reg. SHO short sale price test restriction status"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Short Sale Price Test Status"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = int.from_bytes(self.raw, byteorder="little", signed=False)
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 1

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return str(self.value)


class SinglepriceCrossTrade:
    """Trade resulting from a single-price cross"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Singleprice Cross Trade"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = self.raw.decode("ascii")
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 1

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return self.value


class Size:
    """Aggregate quoted size"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Size"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = int.from_bytes(self.raw, byteorder="little", signed=False)
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 4

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return str(self.value)


class StreamOffset:
    """Byte offset of the data stream"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Stream Offset"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = int.from_bytes(self.raw, byteorder="little", signed=False)
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 8

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return str(self.value)


class Symbol:
    """Security identifier"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Symbol"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = self.raw.decode("ascii")
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 8

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return self.value


class SystemEvent:
    """System event identifier"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "System Event"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = self.raw.decode("ascii")
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 1

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return self.value


class TestSecurity:
    """Symbol is a test security"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Test Security"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = self.raw.decode("ascii")
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 1

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return self.value


class Timestamp:
    """Time stamp of the system event"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Timestamp"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = int.from_bytes(self.raw, byteorder="little", signed=True)
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 8

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return str(self.value)


class TradeId:
    """IEX Generated Identifier. Trade ID is also"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Trade Id"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = int.from_bytes(self.raw, byteorder="little", signed=False)
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 8

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return str(self.value)


class TradeThroughExempt:
    """Trade is not subject to Rule 611"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Trade Through Exempt"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = self.raw.decode("ascii")
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 1

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return self.value


class TradingStatus:
    """Trading status identifier"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Trading Status"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = self.raw.decode("ascii")
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 1

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return self.value


class Unused3:
    """Unused"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Unused 3"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = self.raw.decode("ascii")
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 3

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return self.value


class Unused5:
    """Unused"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Unused 5"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = self.raw.decode("ascii")
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 5

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return self.value


class UpperAuctionCollar:
    """Upper threshold price of the auction collar, if any"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value', 'precision')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Upper Auction Collar"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None
        self.precision = 4

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = int.from_bytes(self.raw, byteorder="little", signed=True)
            self.value = self.value / 10**self.precision
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 8

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return str(self.value)


class Version:
    """Version of transport specification"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Version"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = int.from_bytes(self.raw, byteorder="little", signed=False)
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 1

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return str(self.value)


class WhenIssued:
    """Symbol is a when issued security"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "When Issued"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+self.length]

        if len(self.raw) != self.length:
            self._error = f"Expected {self.length} bytes but received {len(self.raw)}"
            return

        try:
            self.value = self.raw.decode("ascii")
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 1

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return self.value


class AuctionInformationMessage:
    __slots__ = ('_name', '_error', '_length', '_parent', 'auction_type', 'timestamp', 'symbol', 'paired_shares', 'reference_price', 'indicative_clearing_price', 'imbalance_shares', 'imbalance_side', 'extension_number', 'scheduled_auction_time', 'auction_book_clearing_price', 'collar_reference_price', 'lower_auction_collar', 'upper_auction_collar')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Auction Information Message"
        self._error = None
        self._length = 0
        self._parent = parent
        self.auction_type = None
        self.timestamp = None
        self.symbol = None
        self.paired_shares = None
        self.reference_price = None
        self.indicative_clearing_price = None
        self.imbalance_shares = None
        self.imbalance_side = None
        self.extension_number = None
        self.scheduled_auction_time = None
        self.auction_book_clearing_price = None
        self.collar_reference_price = None
        self.lower_auction_collar = None
        self.upper_auction_collar = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        current = offset

        self.auction_type = AuctionType(data, current, self)
        if not self.auction_type.valid:
            self._error = self.auction_type._error
            return

        current += self.auction_type.length

        self.timestamp = Timestamp(data, current, self)
        if not self.timestamp.valid:
            self._error = self.timestamp._error
            return

        current += self.timestamp.length

        self.symbol = Symbol(data, current, self)
        if not self.symbol.valid:
            self._error = self.symbol._error
            return

        current += self.symbol.length

        self.paired_shares = PairedShares(data, current, self)
        if not self.paired_shares.valid:
            self._error = self.paired_shares._error
            return

        current += self.paired_shares.length

        self.reference_price = ReferencePrice(data, current, self)
        if not self.reference_price.valid:
            self._error = self.reference_price._error
            return

        current += self.reference_price.length

        self.indicative_clearing_price = IndicativeClearingPrice(data, current, self)
        if not self.indicative_clearing_price.valid:
            self._error = self.indicative_clearing_price._error
            return

        current += self.indicative_clearing_price.length

        self.imbalance_shares = ImbalanceShares(data, current, self)
        if not self.imbalance_shares.valid:
            self._error = self.imbalance_shares._error
            return

        current += self.imbalance_shares.length

        self.imbalance_side = ImbalanceSide(data, current, self)
        if not self.imbalance_side.valid:
            self._error = self.imbalance_side._error
            return

        current += self.imbalance_side.length

        self.extension_number = ExtensionNumber(data, current, self)
        if not self.extension_number.valid:
            self._error = self.extension_number._error
            return

        current += self.extension_number.length

        self.scheduled_auction_time = ScheduledAuctionTime(data, current, self)
        if not self.scheduled_auction_time.valid:
            self._error = self.scheduled_auction_time._error
            return

        current += self.scheduled_auction_time.length

        self.auction_book_clearing_price = AuctionBookClearingPrice(data, current, self)
        if not self.auction_book_clearing_price.valid:
            self._error = self.auction_book_clearing_price._error
            return

        current += self.auction_book_clearing_price.length

        self.collar_reference_price = CollarReferencePrice(data, current, self)
        if not self.collar_reference_price.valid:
            self._error = self.collar_reference_price._error
            return

        current += self.collar_reference_price.length

        self.lower_auction_collar = LowerAuctionCollar(data, current, self)
        if not self.lower_auction_collar.valid:
            self._error = self.lower_auction_collar._error
            return

        current += self.lower_auction_collar.length

        self.upper_auction_collar = UpperAuctionCollar(data, current, self)
        if not self.upper_auction_collar.valid:
            self._error = self.upper_auction_collar._error
            return

        current += self.upper_auction_collar.length

        self._length = current - offset

    @property
    def valid(self) -> bool:
        return self._error is None

class SaleConditionFlags:
    __slots__ = ('_name', '_error', '_length', '_parent', 'raw', 'unused_3', 'singleprice_cross_trade', 'trade_through_exempt', 'odd_lot', 'extended_hours', 'intermarket_sweep')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Sale Condition Flags"
        self._error = None
        self._length = 1
        self._parent = parent
        self.unused_3 = None
        self.singleprice_cross_trade = None
        self.trade_through_exempt = None
        self.odd_lot = None
        self.extended_hours = None
        self.intermarket_sweep = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+1]
        if len(self.raw) != 1:
            self._error = f"Expected 1 bytes but received {len(self.raw)}"
            return


        try:
            value = int.from_bytes(self.raw, byteorder="little", signed=False)
            self.unused_3 = (value >> 5) & 0x7
            self.singleprice_cross_trade = (value >> 4) & 0x1
            self.trade_through_exempt = (value >> 3) & 0x1
            self.odd_lot = (value >> 2) & 0x1
            self.extended_hours = (value >> 1) & 0x1
            self.intermarket_sweep = value & 0x1
        except Exception as exception:
            self._error = f"Error: {exception}"

    @property
    def valid(self) -> bool:
        return self._error is None

class TradeBreakMessage:
    __slots__ = ('_name', '_error', '_length', '_parent', 'sale_condition_flags', 'timestamp', 'symbol', 'size', 'price', 'trade_id')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Trade Break Message"
        self._error = None
        self._length = 0
        self._parent = parent
        self.sale_condition_flags = None
        self.timestamp = None
        self.symbol = None
        self.size = None
        self.price = None
        self.trade_id = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        current = offset

        self.sale_condition_flags = SaleConditionFlags(data, current, self)
        if not self.sale_condition_flags.valid:
            self._error = self.sale_condition_flags._error
            return

        current += self.sale_condition_flags._length

        self.timestamp = Timestamp(data, current, self)
        if not self.timestamp.valid:
            self._error = self.timestamp._error
            return

        current += self.timestamp.length

        self.symbol = Symbol(data, current, self)
        if not self.symbol.valid:
            self._error = self.symbol._error
            return

        current += self.symbol.length

        self.size = Size(data, current, self)
        if not self.size.valid:
            self._error = self.size._error
            return

        current += self.size.length

        self.price = Price(data, current, self)
        if not self.price.valid:
            self._error = self.price._error
            return

        current += self.price.length

        self.trade_id = TradeId(data, current, self)
        if not self.trade_id.valid:
            self._error = self.trade_id._error
            return

        current += self.trade_id.length

        self._length = current - offset

    @property
    def valid(self) -> bool:
        return self._error is None

class OfficialPriceMessage:
    __slots__ = ('_name', '_error', '_length', '_parent', 'price_type', 'timestamp', 'symbol', 'official_price')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Official Price Message"
        self._error = None
        self._length = 0
        self._parent = parent
        self.price_type = None
        self.timestamp = None
        self.symbol = None
        self.official_price = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        current = offset

        self.price_type = PriceType(data, current, self)
        if not self.price_type.valid:
            self._error = self.price_type._error
            return

        current += self.price_type.length

        self.timestamp = Timestamp(data, current, self)
        if not self.timestamp.valid:
            self._error = self.timestamp._error
            return

        current += self.timestamp.length

        self.symbol = Symbol(data, current, self)
        if not self.symbol.valid:
            self._error = self.symbol._error
            return

        current += self.symbol.length

        self.official_price = OfficialPrice(data, current, self)
        if not self.official_price.valid:
            self._error = self.official_price._error
            return

        current += self.official_price.length

        self._length = current - offset

    @property
    def valid(self) -> bool:
        return self._error is None

class TradeReportMessage:
    __slots__ = ('_name', '_error', '_length', '_parent', 'sale_condition_flags', 'timestamp', 'symbol', 'size', 'price', 'trade_id')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Trade Report Message"
        self._error = None
        self._length = 0
        self._parent = parent
        self.sale_condition_flags = None
        self.timestamp = None
        self.symbol = None
        self.size = None
        self.price = None
        self.trade_id = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        current = offset

        self.sale_condition_flags = SaleConditionFlags(data, current, self)
        if not self.sale_condition_flags.valid:
            self._error = self.sale_condition_flags._error
            return

        current += self.sale_condition_flags._length

        self.timestamp = Timestamp(data, current, self)
        if not self.timestamp.valid:
            self._error = self.timestamp._error
            return

        current += self.timestamp.length

        self.symbol = Symbol(data, current, self)
        if not self.symbol.valid:
            self._error = self.symbol._error
            return

        current += self.symbol.length

        self.size = Size(data, current, self)
        if not self.size.valid:
            self._error = self.size._error
            return

        current += self.size.length

        self.price = Price(data, current, self)
        if not self.price.valid:
            self._error = self.price._error
            return

        current += self.price.length

        self.trade_id = TradeId(data, current, self)
        if not self.trade_id.valid:
            self._error = self.trade_id._error
            return

        current += self.trade_id.length

        self._length = current - offset

    @property
    def valid(self) -> bool:
        return self._error is None

class PriceLevelSellUpdateMessage:
    __slots__ = ('_name', '_error', '_length', '_parent', 'event_flags', 'timestamp', 'symbol', 'size', 'price')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Price Level Sell Update Message"
        self._error = None
        self._length = 0
        self._parent = parent
        self.event_flags = None
        self.timestamp = None
        self.symbol = None
        self.size = None
        self.price = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        current = offset

        self.event_flags = EventFlags(data, current, self)
        if not self.event_flags.valid:
            self._error = self.event_flags._error
            return

        current += self.event_flags.length

        self.timestamp = Timestamp(data, current, self)
        if not self.timestamp.valid:
            self._error = self.timestamp._error
            return

        current += self.timestamp.length

        self.symbol = Symbol(data, current, self)
        if not self.symbol.valid:
            self._error = self.symbol._error
            return

        current += self.symbol.length

        self.size = Size(data, current, self)
        if not self.size.valid:
            self._error = self.size._error
            return

        current += self.size.length

        self.price = Price(data, current, self)
        if not self.price.valid:
            self._error = self.price._error
            return

        current += self.price.length

        self._length = current - offset

    @property
    def valid(self) -> bool:
        return self._error is None

class PriceLevelBuyUpdateMessage:
    __slots__ = ('_name', '_error', '_length', '_parent', 'event_flags', 'timestamp', 'symbol', 'size', 'price')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Price Level Buy Update Message"
        self._error = None
        self._length = 0
        self._parent = parent
        self.event_flags = None
        self.timestamp = None
        self.symbol = None
        self.size = None
        self.price = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        current = offset

        self.event_flags = EventFlags(data, current, self)
        if not self.event_flags.valid:
            self._error = self.event_flags._error
            return

        current += self.event_flags.length

        self.timestamp = Timestamp(data, current, self)
        if not self.timestamp.valid:
            self._error = self.timestamp._error
            return

        current += self.timestamp.length

        self.symbol = Symbol(data, current, self)
        if not self.symbol.valid:
            self._error = self.symbol._error
            return

        current += self.symbol.length

        self.size = Size(data, current, self)
        if not self.size.valid:
            self._error = self.size._error
            return

        current += self.size.length

        self.price = Price(data, current, self)
        if not self.price.valid:
            self._error = self.price._error
            return

        current += self.price.length

        self._length = current - offset

    @property
    def valid(self) -> bool:
        return self._error is None

class SecurityEventMessage:
    __slots__ = ('_name', '_error', '_length', '_parent', 'security_event', 'timestamp', 'symbol')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Security Event Message"
        self._error = None
        self._length = 0
        self._parent = parent
        self.security_event = None
        self.timestamp = None
        self.symbol = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        current = offset

        self.security_event = SecurityEvent(data, current, self)
        if not self.security_event.valid:
            self._error = self.security_event._error
            return

        current += self.security_event.length

        self.timestamp = Timestamp(data, current, self)
        if not self.timestamp.valid:
            self._error = self.timestamp._error
            return

        current += self.timestamp.length

        self.symbol = Symbol(data, current, self)
        if not self.symbol.valid:
            self._error = self.symbol._error
            return

        current += self.symbol.length

        self._length = current - offset

    @property
    def valid(self) -> bool:
        return self._error is None

class ShortSalePriceTestStatusMessage:
    __slots__ = ('_name', '_error', '_length', '_parent', 'short_sale_price_test_status', 'timestamp', 'symbol', 'detail')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Short Sale Price Test Status Message"
        self._error = None
        self._length = 0
        self._parent = parent
        self.short_sale_price_test_status = None
        self.timestamp = None
        self.symbol = None
        self.detail = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        current = offset

        self.short_sale_price_test_status = ShortSalePriceTestStatus(data, current, self)
        if not self.short_sale_price_test_status.valid:
            self._error = self.short_sale_price_test_status._error
            return

        current += self.short_sale_price_test_status.length

        self.timestamp = Timestamp(data, current, self)
        if not self.timestamp.valid:
            self._error = self.timestamp._error
            return

        current += self.timestamp.length

        self.symbol = Symbol(data, current, self)
        if not self.symbol.valid:
            self._error = self.symbol._error
            return

        current += self.symbol.length

        self.detail = Detail(data, current, self)
        if not self.detail.valid:
            self._error = self.detail._error
            return

        current += self.detail.length

        self._length = current - offset

    @property
    def valid(self) -> bool:
        return self._error is None

class OperationalHaltStatusMessage:
    __slots__ = ('_name', '_error', '_length', '_parent', 'operational_halt_status', 'timestamp', 'symbol')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Operational Halt Status Message"
        self._error = None
        self._length = 0
        self._parent = parent
        self.operational_halt_status = None
        self.timestamp = None
        self.symbol = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        current = offset

        self.operational_halt_status = OperationalHaltStatus(data, current, self)
        if not self.operational_halt_status.valid:
            self._error = self.operational_halt_status._error
            return

        current += self.operational_halt_status.length

        self.timestamp = Timestamp(data, current, self)
        if not self.timestamp.valid:
            self._error = self.timestamp._error
            return

        current += self.timestamp.length

        self.symbol = Symbol(data, current, self)
        if not self.symbol.valid:
            self._error = self.symbol._error
            return

        current += self.symbol.length

        self._length = current - offset

    @property
    def valid(self) -> bool:
        return self._error is None

class TradingStatusMessage:
    __slots__ = ('_name', '_error', '_length', '_parent', 'trading_status', 'timestamp', 'symbol', 'reason')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Trading Status Message"
        self._error = None
        self._length = 0
        self._parent = parent
        self.trading_status = None
        self.timestamp = None
        self.symbol = None
        self.reason = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        current = offset

        self.trading_status = TradingStatus(data, current, self)
        if not self.trading_status.valid:
            self._error = self.trading_status._error
            return

        current += self.trading_status.length

        self.timestamp = Timestamp(data, current, self)
        if not self.timestamp.valid:
            self._error = self.timestamp._error
            return

        current += self.timestamp.length

        self.symbol = Symbol(data, current, self)
        if not self.symbol.valid:
            self._error = self.symbol._error
            return

        current += self.symbol.length

        self.reason = Reason(data, current, self)
        if not self.reason.valid:
            self._error = self.reason._error
            return

        current += self.reason.length

        self._length = current - offset

    @property
    def valid(self) -> bool:
        return self._error is None

class SecurityDirectoryFlags:
    __slots__ = ('_name', '_error', '_length', '_parent', 'raw', 'unused_5', 'etp', 'when_issued', 'test_security')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Security Directory Flags"
        self._error = None
        self._length = 1
        self._parent = parent
        self.unused_5 = None
        self.etp = None
        self.when_issued = None
        self.test_security = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        self.raw = data[offset:offset+1]
        if len(self.raw) != 1:
            self._error = f"Expected 1 bytes but received {len(self.raw)}"
            return


        try:
            value = int.from_bytes(self.raw, byteorder="little", signed=False)
            self.unused_5 = (value >> 3) & 0x1F
            self.etp = (value >> 2) & 0x1
            self.when_issued = (value >> 1) & 0x1
            self.test_security = value & 0x1
        except Exception as exception:
            self._error = f"Error: {exception}"

    @property
    def valid(self) -> bool:
        return self._error is None

class SecurityDirectoryMessage:
    __slots__ = ('_name', '_error', '_length', '_parent', 'security_directory_flags', 'timestamp', 'symbol', 'round_lot_size', 'adjusted_poc_price', 'luld_tier')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Security Directory Message"
        self._error = None
        self._length = 0
        self._parent = parent
        self.security_directory_flags = None
        self.timestamp = None
        self.symbol = None
        self.round_lot_size = None
        self.adjusted_poc_price = None
        self.luld_tier = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        current = offset

        self.security_directory_flags = SecurityDirectoryFlags(data, current, self)
        if not self.security_directory_flags.valid:
            self._error = self.security_directory_flags._error
            return

        current += self.security_directory_flags._length

        self.timestamp = Timestamp(data, current, self)
        if not self.timestamp.valid:
            self._error = self.timestamp._error
            return

        current += self.timestamp.length

        self.symbol = Symbol(data, current, self)
        if not self.symbol.valid:
            self._error = self.symbol._error
            return

        current += self.symbol.length

        self.round_lot_size = RoundLotSize(data, current, self)
        if not self.round_lot_size.valid:
            self._error = self.round_lot_size._error
            return

        current += self.round_lot_size.length

        self.adjusted_poc_price = AdjustedPocPrice(data, current, self)
        if not self.adjusted_poc_price.valid:
            self._error = self.adjusted_poc_price._error
            return

        current += self.adjusted_poc_price.length

        self.luld_tier = LuldTier(data, current, self)
        if not self.luld_tier.valid:
            self._error = self.luld_tier._error
            return

        current += self.luld_tier.length

        self._length = current - offset

    @property
    def valid(self) -> bool:
        return self._error is None

class SystemEventMessage:
    __slots__ = ('_name', '_error', '_length', '_parent', 'system_event', 'timestamp')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "System Event Message"
        self._error = None
        self._length = 0
        self._parent = parent
        self.system_event = None
        self.timestamp = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        current = offset

        self.system_event = SystemEvent(data, current, self)
        if not self.system_event.valid:
            self._error = self.system_event._error
            return

        current += self.system_event.length

        self.timestamp = Timestamp(data, current, self)
        if not self.timestamp.valid:
            self._error = self.timestamp._error
            return

        current += self.timestamp.length

        self._length = current - offset

    @property
    def valid(self) -> bool:
        return self._error is None

def MessageData_factory(data: bytes, offset: int, parent, message_type):
    """TODO"""
    match message_type:
        case "S":
            return SystemEventMessage(data, offset, parent)

        case "D":
            return SecurityDirectoryMessage(data, offset, parent)

        case "H":
            return TradingStatusMessage(data, offset, parent)

        case "O":
            return OperationalHaltStatusMessage(data, offset, parent)

        case "P":
            return ShortSalePriceTestStatusMessage(data, offset, parent)

        case "E":
            return SecurityEventMessage(data, offset, parent)

        case "8":
            return PriceLevelBuyUpdateMessage(data, offset, parent)

        case "5":
            return PriceLevelSellUpdateMessage(data, offset, parent)

        case "T":
            return TradeReportMessage(data, offset, parent)

        case "X":
            return OfficialPriceMessage(data, offset, parent)

        case "B":
            return TradeBreakMessage(data, offset, parent)

        case "A":
            return AuctionInformationMessage(data, offset, parent)

        case _:
            return _Unknown(message_type)

class MessageHeader:
    __slots__ = ('_name', '_error', '_length', '_parent', 'message_length', 'message_type')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Message Header"
        self._error = None
        self._length = 0
        self._parent = parent
        self.message_length = None
        self.message_type = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        current = offset

        self.message_length = MessageLength(data, current, self)
        if not self.message_length.valid:
            self._error = self.message_length._error
            return

        current += self.message_length.length

        self.message_type = MessageType(data, current, self)
        if not self.message_type.valid:
            self._error = self.message_type._error
            return

        current += self.message_type.length

        self._length = current - offset

    @property
    def valid(self) -> bool:
        return self._error is None

class Message:
    __slots__ = ('_name', '_error', '_length', '_parent', 'message_header', 'message_data')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Message"
        self._error = None
        self._length = 0
        self._parent = parent
        self.message_header = None
        self.message_data = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        current = offset

        self.message_header = MessageHeader(data, current, self)
        if not self.message_header.valid:
            self._error = self.message_header._error
            return

        current += self.message_header._length

        message_type = self.message_header.message_type.value
        self.message_data = MessageData_factory(data, current, self, message_type)
        if not self.message_data.valid:
            self._error = self.message_data._error
            return

        current += self.message_data._length

        self._length = current - offset

    @property
    def valid(self) -> bool:
        return self._error is None

def Messages_factory(data: bytes, offset: int, parent, message_type):
    """TODO"""
    match message_type:
        case 0:
            return Heartbeat(data, offset, parent)

        case _:
            return _Unknown(message_type)

class IextpHeader:
    __slots__ = ('_name', '_error', '_length', '_parent', 'version', 'reserved', 'message_protocol_id', 'channel_id', 'session_id', 'payload_length', 'message_count', 'stream_offset', 'first_message_sequence_number', 'send_time')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Iextp Header"
        self._error = None
        self._length = 0
        self._parent = parent
        self.version = None
        self.reserved = None
        self.message_protocol_id = None
        self.channel_id = None
        self.session_id = None
        self.payload_length = None
        self.message_count = None
        self.stream_offset = None
        self.first_message_sequence_number = None
        self.send_time = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        current = offset

        self.version = Version(data, current, self)
        if not self.version.valid:
            self._error = self.version._error
            return

        current += self.version.length

        self.reserved = Reserved(data, current, self)
        if not self.reserved.valid:
            self._error = self.reserved._error
            return

        current += self.reserved.length

        self.message_protocol_id = MessageProtocolId(data, current, self)
        if not self.message_protocol_id.valid:
            self._error = self.message_protocol_id._error
            return

        current += self.message_protocol_id.length

        self.channel_id = ChannelId(data, current, self)
        if not self.channel_id.valid:
            self._error = self.channel_id._error
            return

        current += self.channel_id.length

        self.session_id = SessionId(data, current, self)
        if not self.session_id.valid:
            self._error = self.session_id._error
            return

        current += self.session_id.length

        self.payload_length = PayloadLength(data, current, self)
        if not self.payload_length.valid:
            self._error = self.payload_length._error
            return

        current += self.payload_length.length

        self.message_count = MessageCount(data, current, self)
        if not self.message_count.valid:
            self._error = self.message_count._error
            return

        current += self.message_count.length

        self.stream_offset = StreamOffset(data, current, self)
        if not self.stream_offset.valid:
            self._error = self.stream_offset._error
            return

        current += self.stream_offset.length

        self.first_message_sequence_number = FirstMessageSequenceNumber(data, current, self)
        if not self.first_message_sequence_number.valid:
            self._error = self.first_message_sequence_number._error
            return

        current += self.first_message_sequence_number.length

        self.send_time = SendTime(data, current, self)
        if not self.send_time.valid:
            self._error = self.send_time._error
            return

        current += self.send_time.length

        self._length = current - offset

    @property
    def valid(self) -> bool:
        return self._error is None

class Packet:
    __slots__ = ('_name', '_error', 'iextp_header', 'messages')

    def __init__(self, data: bytes) -> None:
        self._name = "Packet"
        self._error = None
        self.iextp_header = None
        self.messages = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        current = 0

        self.iextp_header = IextpHeader(data, current, self)
        if not self.iextp_header.valid:
            self._error = self.iextp_header._error
            return

        current += self.iextp_header._length

        message_type = self.iextp_header.message_count.value
        self.messages = Messages_factory(data, current, self, message_type)
        if not self.messages.valid:
            self._error = self.messages._error
            return

        current += self.messages._length

    @property
    def valid(self) -> bool:
        return self._error is None

