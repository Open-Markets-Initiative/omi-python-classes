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
class Nasdaq:
    _name: str = "NasdaqItchTotalView"
    _version: str = "5.0"

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
        for frame in Nasdaq.frames(path):

            packet = Packet(frame.data)

            if packet.valid:
                yield packet

    @staticmethod
    def messages(path: str | Path):
        for packet in Nasdaq.packets(path):
            for message in packet.messages:
                yield message


### Types ###

class Attribution:
    """Nasdaq market participant identifier associated with the entered order"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Attribution"
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


class AuctionCollarExtension:
    """Indicates the number of extensions to the Reopening Auction"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Auction Collar Extension"
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
            self.value = int.from_bytes(self.raw, byteorder="big", signed=False)
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


class AuctionCollarReferencePrice:
    """Reference price used to set the auction collars"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value', 'precision')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Auction Collar Reference Price"
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
            self.value = int.from_bytes(self.raw, byteorder="big", signed=False)
            self.value = self.value / 10**self.precision
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


class Authenticity:
    """Denotes if an issue or quoting participant record is set-up in NASDAQ systems in a live/production, test, or demo state"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Authenticity"
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


class BreachedLevel:
    """Denotes the MWCB Level that was breached"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Breached Level"
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


class BuySellIndicator:
    """The type of order being added"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Buy Sell Indicator"
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


class CanceledShares:
    """The number of shares being removed from the display size of the order as the result of a cancellation"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Canceled Shares"
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
            self.value = int.from_bytes(self.raw, byteorder="big", signed=False)
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


class CrossPrice:
    """The price at which the cross occurred"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value', 'precision')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Cross Price"
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
            self.value = int.from_bytes(self.raw, byteorder="big", signed=False)
            self.value = self.value / 10**self.precision
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


class CrossShares:
    """The number of shares matched in the Nasdaq Cross"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Cross Shares"
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
            self.value = int.from_bytes(self.raw, byteorder="big", signed=False)
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


class CrossType:
    """The Nasdaq cross session for which the message is being generated"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Cross Type"
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


class CurrentReferencePrice:
    """The price at which the NOII shares are being calculated"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value', 'precision')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Current Reference Price"
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
            self.value = int.from_bytes(self.raw, byteorder="big", signed=False)
            self.value = self.value / 10**self.precision
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


class EtpFlag:
    """Indicates whether the security is an exchange traded product"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Etp Flag"
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


class EtpLeverageFactor:
    """Tracks the integral relationship of the ETP to the underlying index"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Etp Leverage Factor"
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
            self.value = int.from_bytes(self.raw, byteorder="big", signed=False)
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


class EventCode:
    """System Event Codes"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Event Code"
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


class ExecutedShares:
    """The number of shares executed"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Executed Shares"
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
            self.value = int.from_bytes(self.raw, byteorder="big", signed=False)
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


class ExecutionPrice:
    """The price at which the order execution occurred"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value', 'precision')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Execution Price"
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
            self.value = int.from_bytes(self.raw, byteorder="big", signed=False)
            self.value = self.value / 10**self.precision
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


class FarPrice:
    """A hypothetical auction-clearing price for cross orders only"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value', 'precision')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Far Price"
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
            self.value = int.from_bytes(self.raw, byteorder="big", signed=False)
            self.value = self.value / 10**self.precision
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


class FinancialStatusIndicator:
    """Indicates when a firm is not in compliance with NASDAQ continued listing requirements"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Financial Status Indicator"
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


class ImbalanceDirection:
    """The market side of the order imbalance"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Imbalance Direction"
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


class ImbalanceShares:
    """The number of shares not paired at the Current Reference Price"""
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
            self.value = int.from_bytes(self.raw, byteorder="big", signed=False)
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


class InterestFlag:
    """Interest Flag"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Interest Flag"
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


class InverseIndicator:
    """Indicates the directional relationship between the ETP and underlying index. Example: An ETP Leverage Factor of 3 and an Inverse value of 'Y' indicates the ETP will decrease by a value of 3."""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Inverse Indicator"
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


class IpoFlag:
    """Indicates if the NASDAQ security is set up for IPO release"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Ipo Flag"
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


class IpoPrice:
    """Denotes the IPO price to be used for intraday net change calculations"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value', 'precision')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Ipo Price"
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
            self.value = int.from_bytes(self.raw, byteorder="big", signed=False)
            self.value = self.value / 10**self.precision
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


class IpoQuotationReleaseQualifier:
    """IPO Quotation Release Qualifier"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Ipo Quotation Release Qualifier"
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


class IpoQuotationReleaseTime:
    """Denotes the IPO release time, in seconds since midnight, for quotation to the nearest second"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Ipo Quotation Release Time"
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
            self.value = int.from_bytes(self.raw, byteorder="big", signed=False)
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


class IssueClassification:
    """Identifies the security class for the issue as assigned by NASDAQ"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Issue Classification"
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


class IssueSubType:
    """Identifies the security sub-type for the issue as assigned by NASDAQ"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Issue Sub Type"
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
        return 2

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return self.value


class Level1:
    """Denotes the MWCB Level 1 Value."""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value', 'precision')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Level 1"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None
        self.precision = 8

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
            self.value = int.from_bytes(self.raw, byteorder="big", signed=False)
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


class Level2:
    """Denotes the MWCB Level 2 Value."""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value', 'precision')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Level 2"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None
        self.precision = 8

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
            self.value = int.from_bytes(self.raw, byteorder="big", signed=False)
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


class Level3:
    """Denotes the MWCB Level 3 Value."""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value', 'precision')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Level 3"
        self._error = None
        self._parent = parent
        self.raw = None
        self.value = None
        self.precision = 8

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
            self.value = int.from_bytes(self.raw, byteorder="big", signed=False)
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


class LocateCode:
    """Locate code identifying the security"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Locate Code"
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
            self.value = int.from_bytes(self.raw, byteorder="big", signed=False)
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


class LowerAuctionCollarPrice:
    """Indicates the price of the lower auction collar threshold"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value', 'precision')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Lower Auction Collar Price"
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
            self.value = int.from_bytes(self.raw, byteorder="big", signed=False)
            self.value = self.value / 10**self.precision
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


class LowerPriceRangeCollar:
    """Indicates the price of the Lower Auction Collar Threshold"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value', 'precision')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Lower Price Range Collar"
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
            self.value = int.from_bytes(self.raw, byteorder="big", signed=False)
            self.value = self.value / 10**self.precision
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


class LuldReferencePriceTier:
    """Indicates which Limit Up / Limit Down price band calculation parameter is to be used for the instrument"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Luld Reference Price Tier"
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


class MarketCategory:
    """Indicates listing market or listing market tier for the issue"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Market Category"
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


class MarketCode:
    """Market Code"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Market Code"
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


class MarketMakerMode:
    """Indicates the quoting participant's registration status in relation to SEC Rules 101 and 104 of Regulation M"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Market Maker Mode"
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


class MarketParticipantState:
    """Indicates the market participant's current registration status in the issue"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Market Participant State"
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


class MatchNumber:
    """The Nasdaq generated day-unique Match Number of this execution"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Match Number"
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
            self.value = int.from_bytes(self.raw, byteorder="big", signed=False)
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


class MaximumAllowablePrice:
    """80% above Registration Statement Highest Price"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value', 'precision')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Maximum Allowable Price"
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
            self.value = int.from_bytes(self.raw, byteorder="big", signed=False)
            self.value = self.value / 10**self.precision
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


class MessageCount:
    """Number of messages to follow this header"""
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
            self.value = int.from_bytes(self.raw, byteorder="big", signed=False)
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
    """Length of data message not including this field"""
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
            self.value = int.from_bytes(self.raw, byteorder="big", signed=False)
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


class MinimumAllowablePrice:
    """20% below Registration Statement Lower Price"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value', 'precision')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Minimum Allowable Price"
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
            self.value = int.from_bytes(self.raw, byteorder="big", signed=False)
            self.value = self.value / 10**self.precision
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


class Mpid:
    """Denotes the market participant identifier for which the position message is being generated"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Mpid"
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


class NearExecutionPrice:
    """The current reference price when the DLCR volatility test has successfully passed"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value', 'precision')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Near Execution Price"
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
            self.value = int.from_bytes(self.raw, byteorder="big", signed=False)
            self.value = self.value / 10**self.precision
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


class NearExecutionTime:
    """The time at which the Near Execution Price was determined"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Near Execution Time"
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
            self.value = int.from_bytes(self.raw, byteorder="big", signed=False)
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


class NearPrice:
    """A hypothetical auction-clearing price for cross orders as well as continuous orders"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value', 'precision')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Near Price"
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
            self.value = int.from_bytes(self.raw, byteorder="big", signed=False)
            self.value = self.value / 10**self.precision
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


class NewOrderReferenceNumber:
    """The new reference number for this order at time of replacement"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "New Order Reference Number"
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
            self.value = int.from_bytes(self.raw, byteorder="big", signed=False)
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


class OpenEligibilityStatus:
    """Indicates if the security is eligible to be released for trading"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Open Eligibility Status"
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


class OperationalHaltAction:
    """Indicates the operational halt action for the security"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Operational Halt Action"
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


class OrderReferenceNumber:
    """The unique reference number assigned to the new order at the time of receipt"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Order Reference Number"
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
            self.value = int.from_bytes(self.raw, byteorder="big", signed=False)
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


class OriginalOrderReferenceNumber:
    """The original reference number of the order being replaced"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Original Order Reference Number"
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
            self.value = int.from_bytes(self.raw, byteorder="big", signed=False)
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


class PairedShares:
    """The total number of shares that are eligible to be matched at the Current Reference Price"""
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
            self.value = int.from_bytes(self.raw, byteorder="big", signed=False)
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


class Price:
    """The display price of the new order"""
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
            self.value = int.from_bytes(self.raw, byteorder="big", signed=False)
            self.value = self.value / 10**self.precision
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


class PriceVariationIndicator:
    """Indicates the absolute value of the percentage of deviation of the Near Indicative Clearing Price to the nearest Current Reference Price"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Price Variation Indicator"
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


class PrimaryMarketMaker:
    """Indicates if the market participant firm qualifies as a Primary Market Maker in accordance with NASDAQ marketplace rules"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Primary Market Maker"
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


class Printable:
    """Indicates if the execution should be reflected on time and sale displays and volume calculations"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Printable"
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


class ReasonCode:
    """Trading Action reason"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Reason Code"
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


class RegShoAction:
    """Denotes the Reg SHO Short Sale Price Test Restriction status for the issue at the time of the message dissemination"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Reg Sho Action"
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


class Reserved:
    """Reserved"""
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
    """Denotes the number of shares that represent a round lot for the issue"""
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
            self.value = int.from_bytes(self.raw, byteorder="big", signed=False)
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


class RoundLotsOnly:
    """Indicates if Nasdaq system limits order entry for issue"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Round Lots Only"
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


class SequenceNumber:
    """Sequence number of the first message to follow this header"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Sequence Number"
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
            self.value = int.from_bytes(self.raw, byteorder="big", signed=False)
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


class Session:
    """Identity of the multicast session"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Session"
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
        return 10

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return self.value


class Shares:
    """The total number of shares associated with the order being added to the book"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Shares"
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
            self.value = int.from_bytes(self.raw, byteorder="big", signed=False)
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


class ShortSaleThresholdIndicator:
    """Indicates if a security is subject to mandatory close-out of short sales under SEC Rule 203(b)(3)."""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Short Sale Threshold Indicator"
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


class Stock:
    """Denotes the security symbol for the issue in the NASDAQ execution system."""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Stock"
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


class StockLocate:
    """Locate Code uniquely assigned to the security symbol for the day"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Stock Locate"
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
            self.value = int.from_bytes(self.raw, byteorder="big", signed=False)
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


class Timestamp:
    """Nanoseconds since midnight"""
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
            self.value = int.from_bytes(self.raw, byteorder="big", signed=False)
        except Exception as exception:
            self._error = f"Error: {exception}, data: [{data}]"

    @property
    def length(self) -> int:
        return 6

    @property
    def valid(self) -> bool:
        return self._error is None

    def __repr__(self) -> str:
        return str(self.value)


class TrackingNumber:
    """Nasdaq internal tracking number"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Tracking Number"
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
            self.value = int.from_bytes(self.raw, byteorder="big", signed=False)
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


class TradingState:
    """Indicates the current trading state for the stock"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Trading State"
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


class UpperAuctionCollarPrice:
    """Indicates the price of the upper auction collar threshold"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value', 'precision')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Upper Auction Collar Price"
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
            self.value = int.from_bytes(self.raw, byteorder="big", signed=False)
            self.value = self.value / 10**self.precision
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


class UpperPriceRangeCollar:
    """Indicates the price of the Upper Auction Collar Threshold"""
    __slots__ = ('_name', '_error', '_parent', 'raw', 'value', 'precision')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Upper Price Range Collar"
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
            self.value = int.from_bytes(self.raw, byteorder="big", signed=False)
            self.value = self.value / 10**self.precision
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


class DirectListingWithCapitalRaisePriceDiscoveryMessage:
    __slots__ = ('_name', '_error', '_length', '_parent', 'stock_locate', 'tracking_number', 'timestamp', 'stock', 'open_eligibility_status', 'minimum_allowable_price', 'maximum_allowable_price', 'near_execution_price', 'near_execution_time', 'lower_price_range_collar', 'upper_price_range_collar')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Direct Listing With Capital Raise Price Discovery Message"
        self._error = None
        self._length = 0
        self._parent = parent
        self.stock_locate = None
        self.tracking_number = None
        self.timestamp = None
        self.stock = None
        self.open_eligibility_status = None
        self.minimum_allowable_price = None
        self.maximum_allowable_price = None
        self.near_execution_price = None
        self.near_execution_time = None
        self.lower_price_range_collar = None
        self.upper_price_range_collar = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        current = offset

        self.stock_locate = StockLocate(data, current, self)
        if not self.stock_locate.valid:
            self._error = self.stock_locate._error
            return

        current += self.stock_locate.length

        self.tracking_number = TrackingNumber(data, current, self)
        if not self.tracking_number.valid:
            self._error = self.tracking_number._error
            return

        current += self.tracking_number.length

        self.timestamp = Timestamp(data, current, self)
        if not self.timestamp.valid:
            self._error = self.timestamp._error
            return

        current += self.timestamp.length

        self.stock = Stock(data, current, self)
        if not self.stock.valid:
            self._error = self.stock._error
            return

        current += self.stock.length

        self.open_eligibility_status = OpenEligibilityStatus(data, current, self)
        if not self.open_eligibility_status.valid:
            self._error = self.open_eligibility_status._error
            return

        current += self.open_eligibility_status.length

        self.minimum_allowable_price = MinimumAllowablePrice(data, current, self)
        if not self.minimum_allowable_price.valid:
            self._error = self.minimum_allowable_price._error
            return

        current += self.minimum_allowable_price.length

        self.maximum_allowable_price = MaximumAllowablePrice(data, current, self)
        if not self.maximum_allowable_price.valid:
            self._error = self.maximum_allowable_price._error
            return

        current += self.maximum_allowable_price.length

        self.near_execution_price = NearExecutionPrice(data, current, self)
        if not self.near_execution_price.valid:
            self._error = self.near_execution_price._error
            return

        current += self.near_execution_price.length

        self.near_execution_time = NearExecutionTime(data, current, self)
        if not self.near_execution_time.valid:
            self._error = self.near_execution_time._error
            return

        current += self.near_execution_time.length

        self.lower_price_range_collar = LowerPriceRangeCollar(data, current, self)
        if not self.lower_price_range_collar.valid:
            self._error = self.lower_price_range_collar._error
            return

        current += self.lower_price_range_collar.length

        self.upper_price_range_collar = UpperPriceRangeCollar(data, current, self)
        if not self.upper_price_range_collar.valid:
            self._error = self.upper_price_range_collar._error
            return

        current += self.upper_price_range_collar.length

        self._length = current - offset

    @property
    def valid(self) -> bool:
        return self._error is None

class RetailPriceImprovementIndicatorMessage:
    __slots__ = ('_name', '_error', '_length', '_parent', 'stock_locate', 'tracking_number', 'timestamp', 'stock', 'interest_flag')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Retail Price Improvement Indicator Message"
        self._error = None
        self._length = 0
        self._parent = parent
        self.stock_locate = None
        self.tracking_number = None
        self.timestamp = None
        self.stock = None
        self.interest_flag = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        current = offset

        self.stock_locate = StockLocate(data, current, self)
        if not self.stock_locate.valid:
            self._error = self.stock_locate._error
            return

        current += self.stock_locate.length

        self.tracking_number = TrackingNumber(data, current, self)
        if not self.tracking_number.valid:
            self._error = self.tracking_number._error
            return

        current += self.tracking_number.length

        self.timestamp = Timestamp(data, current, self)
        if not self.timestamp.valid:
            self._error = self.timestamp._error
            return

        current += self.timestamp.length

        self.stock = Stock(data, current, self)
        if not self.stock.valid:
            self._error = self.stock._error
            return

        current += self.stock.length

        self.interest_flag = InterestFlag(data, current, self)
        if not self.interest_flag.valid:
            self._error = self.interest_flag._error
            return

        current += self.interest_flag.length

        self._length = current - offset

    @property
    def valid(self) -> bool:
        return self._error is None

class NetOrderImbalanceIndicatorMessage:
    __slots__ = ('_name', '_error', '_length', '_parent', 'stock_locate', 'tracking_number', 'timestamp', 'paired_shares', 'imbalance_shares', 'imbalance_direction', 'stock', 'far_price', 'near_price', 'current_reference_price', 'cross_type', 'price_variation_indicator')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Net Order Imbalance Indicator Message"
        self._error = None
        self._length = 0
        self._parent = parent
        self.stock_locate = None
        self.tracking_number = None
        self.timestamp = None
        self.paired_shares = None
        self.imbalance_shares = None
        self.imbalance_direction = None
        self.stock = None
        self.far_price = None
        self.near_price = None
        self.current_reference_price = None
        self.cross_type = None
        self.price_variation_indicator = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        current = offset

        self.stock_locate = StockLocate(data, current, self)
        if not self.stock_locate.valid:
            self._error = self.stock_locate._error
            return

        current += self.stock_locate.length

        self.tracking_number = TrackingNumber(data, current, self)
        if not self.tracking_number.valid:
            self._error = self.tracking_number._error
            return

        current += self.tracking_number.length

        self.timestamp = Timestamp(data, current, self)
        if not self.timestamp.valid:
            self._error = self.timestamp._error
            return

        current += self.timestamp.length

        self.paired_shares = PairedShares(data, current, self)
        if not self.paired_shares.valid:
            self._error = self.paired_shares._error
            return

        current += self.paired_shares.length

        self.imbalance_shares = ImbalanceShares(data, current, self)
        if not self.imbalance_shares.valid:
            self._error = self.imbalance_shares._error
            return

        current += self.imbalance_shares.length

        self.imbalance_direction = ImbalanceDirection(data, current, self)
        if not self.imbalance_direction.valid:
            self._error = self.imbalance_direction._error
            return

        current += self.imbalance_direction.length

        self.stock = Stock(data, current, self)
        if not self.stock.valid:
            self._error = self.stock._error
            return

        current += self.stock.length

        self.far_price = FarPrice(data, current, self)
        if not self.far_price.valid:
            self._error = self.far_price._error
            return

        current += self.far_price.length

        self.near_price = NearPrice(data, current, self)
        if not self.near_price.valid:
            self._error = self.near_price._error
            return

        current += self.near_price.length

        self.current_reference_price = CurrentReferencePrice(data, current, self)
        if not self.current_reference_price.valid:
            self._error = self.current_reference_price._error
            return

        current += self.current_reference_price.length

        self.cross_type = CrossType(data, current, self)
        if not self.cross_type.valid:
            self._error = self.cross_type._error
            return

        current += self.cross_type.length

        self.price_variation_indicator = PriceVariationIndicator(data, current, self)
        if not self.price_variation_indicator.valid:
            self._error = self.price_variation_indicator._error
            return

        current += self.price_variation_indicator.length

        self._length = current - offset

    @property
    def valid(self) -> bool:
        return self._error is None

class BrokenTradeMessage:
    __slots__ = ('_name', '_error', '_length', '_parent', 'stock_locate', 'tracking_number', 'timestamp', 'match_number')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Broken Trade Message"
        self._error = None
        self._length = 0
        self._parent = parent
        self.stock_locate = None
        self.tracking_number = None
        self.timestamp = None
        self.match_number = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        current = offset

        self.stock_locate = StockLocate(data, current, self)
        if not self.stock_locate.valid:
            self._error = self.stock_locate._error
            return

        current += self.stock_locate.length

        self.tracking_number = TrackingNumber(data, current, self)
        if not self.tracking_number.valid:
            self._error = self.tracking_number._error
            return

        current += self.tracking_number.length

        self.timestamp = Timestamp(data, current, self)
        if not self.timestamp.valid:
            self._error = self.timestamp._error
            return

        current += self.timestamp.length

        self.match_number = MatchNumber(data, current, self)
        if not self.match_number.valid:
            self._error = self.match_number._error
            return

        current += self.match_number.length

        self._length = current - offset

    @property
    def valid(self) -> bool:
        return self._error is None

class CrossTradeMessage:
    __slots__ = ('_name', '_error', '_length', '_parent', 'stock_locate', 'tracking_number', 'timestamp', 'cross_shares', 'stock', 'cross_price', 'match_number', 'cross_type')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Cross Trade Message"
        self._error = None
        self._length = 0
        self._parent = parent
        self.stock_locate = None
        self.tracking_number = None
        self.timestamp = None
        self.cross_shares = None
        self.stock = None
        self.cross_price = None
        self.match_number = None
        self.cross_type = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        current = offset

        self.stock_locate = StockLocate(data, current, self)
        if not self.stock_locate.valid:
            self._error = self.stock_locate._error
            return

        current += self.stock_locate.length

        self.tracking_number = TrackingNumber(data, current, self)
        if not self.tracking_number.valid:
            self._error = self.tracking_number._error
            return

        current += self.tracking_number.length

        self.timestamp = Timestamp(data, current, self)
        if not self.timestamp.valid:
            self._error = self.timestamp._error
            return

        current += self.timestamp.length

        self.cross_shares = CrossShares(data, current, self)
        if not self.cross_shares.valid:
            self._error = self.cross_shares._error
            return

        current += self.cross_shares.length

        self.stock = Stock(data, current, self)
        if not self.stock.valid:
            self._error = self.stock._error
            return

        current += self.stock.length

        self.cross_price = CrossPrice(data, current, self)
        if not self.cross_price.valid:
            self._error = self.cross_price._error
            return

        current += self.cross_price.length

        self.match_number = MatchNumber(data, current, self)
        if not self.match_number.valid:
            self._error = self.match_number._error
            return

        current += self.match_number.length

        self.cross_type = CrossType(data, current, self)
        if not self.cross_type.valid:
            self._error = self.cross_type._error
            return

        current += self.cross_type.length

        self._length = current - offset

    @property
    def valid(self) -> bool:
        return self._error is None

class NonCrossTradeMessage:
    __slots__ = ('_name', '_error', '_length', '_parent', 'stock_locate', 'tracking_number', 'timestamp', 'order_reference_number', 'buy_sell_indicator', 'shares', 'stock', 'price', 'match_number')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Non Cross Trade Message"
        self._error = None
        self._length = 0
        self._parent = parent
        self.stock_locate = None
        self.tracking_number = None
        self.timestamp = None
        self.order_reference_number = None
        self.buy_sell_indicator = None
        self.shares = None
        self.stock = None
        self.price = None
        self.match_number = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        current = offset

        self.stock_locate = StockLocate(data, current, self)
        if not self.stock_locate.valid:
            self._error = self.stock_locate._error
            return

        current += self.stock_locate.length

        self.tracking_number = TrackingNumber(data, current, self)
        if not self.tracking_number.valid:
            self._error = self.tracking_number._error
            return

        current += self.tracking_number.length

        self.timestamp = Timestamp(data, current, self)
        if not self.timestamp.valid:
            self._error = self.timestamp._error
            return

        current += self.timestamp.length

        self.order_reference_number = OrderReferenceNumber(data, current, self)
        if not self.order_reference_number.valid:
            self._error = self.order_reference_number._error
            return

        current += self.order_reference_number.length

        self.buy_sell_indicator = BuySellIndicator(data, current, self)
        if not self.buy_sell_indicator.valid:
            self._error = self.buy_sell_indicator._error
            return

        current += self.buy_sell_indicator.length

        self.shares = Shares(data, current, self)
        if not self.shares.valid:
            self._error = self.shares._error
            return

        current += self.shares.length

        self.stock = Stock(data, current, self)
        if not self.stock.valid:
            self._error = self.stock._error
            return

        current += self.stock.length

        self.price = Price(data, current, self)
        if not self.price.valid:
            self._error = self.price._error
            return

        current += self.price.length

        self.match_number = MatchNumber(data, current, self)
        if not self.match_number.valid:
            self._error = self.match_number._error
            return

        current += self.match_number.length

        self._length = current - offset

    @property
    def valid(self) -> bool:
        return self._error is None

class OrderReplaceMessage:
    __slots__ = ('_name', '_error', '_length', '_parent', 'stock_locate', 'tracking_number', 'timestamp', 'original_order_reference_number', 'new_order_reference_number', 'shares', 'price')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Order Replace Message"
        self._error = None
        self._length = 0
        self._parent = parent
        self.stock_locate = None
        self.tracking_number = None
        self.timestamp = None
        self.original_order_reference_number = None
        self.new_order_reference_number = None
        self.shares = None
        self.price = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        current = offset

        self.stock_locate = StockLocate(data, current, self)
        if not self.stock_locate.valid:
            self._error = self.stock_locate._error
            return

        current += self.stock_locate.length

        self.tracking_number = TrackingNumber(data, current, self)
        if not self.tracking_number.valid:
            self._error = self.tracking_number._error
            return

        current += self.tracking_number.length

        self.timestamp = Timestamp(data, current, self)
        if not self.timestamp.valid:
            self._error = self.timestamp._error
            return

        current += self.timestamp.length

        self.original_order_reference_number = OriginalOrderReferenceNumber(data, current, self)
        if not self.original_order_reference_number.valid:
            self._error = self.original_order_reference_number._error
            return

        current += self.original_order_reference_number.length

        self.new_order_reference_number = NewOrderReferenceNumber(data, current, self)
        if not self.new_order_reference_number.valid:
            self._error = self.new_order_reference_number._error
            return

        current += self.new_order_reference_number.length

        self.shares = Shares(data, current, self)
        if not self.shares.valid:
            self._error = self.shares._error
            return

        current += self.shares.length

        self.price = Price(data, current, self)
        if not self.price.valid:
            self._error = self.price._error
            return

        current += self.price.length

        self._length = current - offset

    @property
    def valid(self) -> bool:
        return self._error is None

class OrderDeleteMessage:
    __slots__ = ('_name', '_error', '_length', '_parent', 'stock_locate', 'tracking_number', 'timestamp', 'order_reference_number')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Order Delete Message"
        self._error = None
        self._length = 0
        self._parent = parent
        self.stock_locate = None
        self.tracking_number = None
        self.timestamp = None
        self.order_reference_number = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        current = offset

        self.stock_locate = StockLocate(data, current, self)
        if not self.stock_locate.valid:
            self._error = self.stock_locate._error
            return

        current += self.stock_locate.length

        self.tracking_number = TrackingNumber(data, current, self)
        if not self.tracking_number.valid:
            self._error = self.tracking_number._error
            return

        current += self.tracking_number.length

        self.timestamp = Timestamp(data, current, self)
        if not self.timestamp.valid:
            self._error = self.timestamp._error
            return

        current += self.timestamp.length

        self.order_reference_number = OrderReferenceNumber(data, current, self)
        if not self.order_reference_number.valid:
            self._error = self.order_reference_number._error
            return

        current += self.order_reference_number.length

        self._length = current - offset

    @property
    def valid(self) -> bool:
        return self._error is None

class OrderCancelMessage:
    __slots__ = ('_name', '_error', '_length', '_parent', 'stock_locate', 'tracking_number', 'timestamp', 'order_reference_number', 'canceled_shares')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Order Cancel Message"
        self._error = None
        self._length = 0
        self._parent = parent
        self.stock_locate = None
        self.tracking_number = None
        self.timestamp = None
        self.order_reference_number = None
        self.canceled_shares = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        current = offset

        self.stock_locate = StockLocate(data, current, self)
        if not self.stock_locate.valid:
            self._error = self.stock_locate._error
            return

        current += self.stock_locate.length

        self.tracking_number = TrackingNumber(data, current, self)
        if not self.tracking_number.valid:
            self._error = self.tracking_number._error
            return

        current += self.tracking_number.length

        self.timestamp = Timestamp(data, current, self)
        if not self.timestamp.valid:
            self._error = self.timestamp._error
            return

        current += self.timestamp.length

        self.order_reference_number = OrderReferenceNumber(data, current, self)
        if not self.order_reference_number.valid:
            self._error = self.order_reference_number._error
            return

        current += self.order_reference_number.length

        self.canceled_shares = CanceledShares(data, current, self)
        if not self.canceled_shares.valid:
            self._error = self.canceled_shares._error
            return

        current += self.canceled_shares.length

        self._length = current - offset

    @property
    def valid(self) -> bool:
        return self._error is None

class OrderExecutedWithPriceMessage:
    __slots__ = ('_name', '_error', '_length', '_parent', 'stock_locate', 'tracking_number', 'timestamp', 'order_reference_number', 'executed_shares', 'match_number', 'printable', 'execution_price')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Order Executed With Price Message"
        self._error = None
        self._length = 0
        self._parent = parent
        self.stock_locate = None
        self.tracking_number = None
        self.timestamp = None
        self.order_reference_number = None
        self.executed_shares = None
        self.match_number = None
        self.printable = None
        self.execution_price = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        current = offset

        self.stock_locate = StockLocate(data, current, self)
        if not self.stock_locate.valid:
            self._error = self.stock_locate._error
            return

        current += self.stock_locate.length

        self.tracking_number = TrackingNumber(data, current, self)
        if not self.tracking_number.valid:
            self._error = self.tracking_number._error
            return

        current += self.tracking_number.length

        self.timestamp = Timestamp(data, current, self)
        if not self.timestamp.valid:
            self._error = self.timestamp._error
            return

        current += self.timestamp.length

        self.order_reference_number = OrderReferenceNumber(data, current, self)
        if not self.order_reference_number.valid:
            self._error = self.order_reference_number._error
            return

        current += self.order_reference_number.length

        self.executed_shares = ExecutedShares(data, current, self)
        if not self.executed_shares.valid:
            self._error = self.executed_shares._error
            return

        current += self.executed_shares.length

        self.match_number = MatchNumber(data, current, self)
        if not self.match_number.valid:
            self._error = self.match_number._error
            return

        current += self.match_number.length

        self.printable = Printable(data, current, self)
        if not self.printable.valid:
            self._error = self.printable._error
            return

        current += self.printable.length

        self.execution_price = ExecutionPrice(data, current, self)
        if not self.execution_price.valid:
            self._error = self.execution_price._error
            return

        current += self.execution_price.length

        self._length = current - offset

    @property
    def valid(self) -> bool:
        return self._error is None

class OrderExecutedMessage:
    __slots__ = ('_name', '_error', '_length', '_parent', 'stock_locate', 'tracking_number', 'timestamp', 'order_reference_number', 'executed_shares', 'match_number')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Order Executed Message"
        self._error = None
        self._length = 0
        self._parent = parent
        self.stock_locate = None
        self.tracking_number = None
        self.timestamp = None
        self.order_reference_number = None
        self.executed_shares = None
        self.match_number = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        current = offset

        self.stock_locate = StockLocate(data, current, self)
        if not self.stock_locate.valid:
            self._error = self.stock_locate._error
            return

        current += self.stock_locate.length

        self.tracking_number = TrackingNumber(data, current, self)
        if not self.tracking_number.valid:
            self._error = self.tracking_number._error
            return

        current += self.tracking_number.length

        self.timestamp = Timestamp(data, current, self)
        if not self.timestamp.valid:
            self._error = self.timestamp._error
            return

        current += self.timestamp.length

        self.order_reference_number = OrderReferenceNumber(data, current, self)
        if not self.order_reference_number.valid:
            self._error = self.order_reference_number._error
            return

        current += self.order_reference_number.length

        self.executed_shares = ExecutedShares(data, current, self)
        if not self.executed_shares.valid:
            self._error = self.executed_shares._error
            return

        current += self.executed_shares.length

        self.match_number = MatchNumber(data, current, self)
        if not self.match_number.valid:
            self._error = self.match_number._error
            return

        current += self.match_number.length

        self._length = current - offset

    @property
    def valid(self) -> bool:
        return self._error is None

class AddOrderWithMpidAttributionMessage:
    __slots__ = ('_name', '_error', '_length', '_parent', 'stock_locate', 'tracking_number', 'timestamp', 'order_reference_number', 'buy_sell_indicator', 'shares', 'stock', 'price', 'attribution')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Add Order With Mpid Attribution Message"
        self._error = None
        self._length = 0
        self._parent = parent
        self.stock_locate = None
        self.tracking_number = None
        self.timestamp = None
        self.order_reference_number = None
        self.buy_sell_indicator = None
        self.shares = None
        self.stock = None
        self.price = None
        self.attribution = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        current = offset

        self.stock_locate = StockLocate(data, current, self)
        if not self.stock_locate.valid:
            self._error = self.stock_locate._error
            return

        current += self.stock_locate.length

        self.tracking_number = TrackingNumber(data, current, self)
        if not self.tracking_number.valid:
            self._error = self.tracking_number._error
            return

        current += self.tracking_number.length

        self.timestamp = Timestamp(data, current, self)
        if not self.timestamp.valid:
            self._error = self.timestamp._error
            return

        current += self.timestamp.length

        self.order_reference_number = OrderReferenceNumber(data, current, self)
        if not self.order_reference_number.valid:
            self._error = self.order_reference_number._error
            return

        current += self.order_reference_number.length

        self.buy_sell_indicator = BuySellIndicator(data, current, self)
        if not self.buy_sell_indicator.valid:
            self._error = self.buy_sell_indicator._error
            return

        current += self.buy_sell_indicator.length

        self.shares = Shares(data, current, self)
        if not self.shares.valid:
            self._error = self.shares._error
            return

        current += self.shares.length

        self.stock = Stock(data, current, self)
        if not self.stock.valid:
            self._error = self.stock._error
            return

        current += self.stock.length

        self.price = Price(data, current, self)
        if not self.price.valid:
            self._error = self.price._error
            return

        current += self.price.length

        self.attribution = Attribution(data, current, self)
        if not self.attribution.valid:
            self._error = self.attribution._error
            return

        current += self.attribution.length

        self._length = current - offset

    @property
    def valid(self) -> bool:
        return self._error is None

class AddOrderNoMpidAttributionMessage:
    __slots__ = ('_name', '_error', '_length', '_parent', 'stock_locate', 'tracking_number', 'timestamp', 'order_reference_number', 'buy_sell_indicator', 'shares', 'stock', 'price')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Add Order No Mpid Attribution Message"
        self._error = None
        self._length = 0
        self._parent = parent
        self.stock_locate = None
        self.tracking_number = None
        self.timestamp = None
        self.order_reference_number = None
        self.buy_sell_indicator = None
        self.shares = None
        self.stock = None
        self.price = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        current = offset

        self.stock_locate = StockLocate(data, current, self)
        if not self.stock_locate.valid:
            self._error = self.stock_locate._error
            return

        current += self.stock_locate.length

        self.tracking_number = TrackingNumber(data, current, self)
        if not self.tracking_number.valid:
            self._error = self.tracking_number._error
            return

        current += self.tracking_number.length

        self.timestamp = Timestamp(data, current, self)
        if not self.timestamp.valid:
            self._error = self.timestamp._error
            return

        current += self.timestamp.length

        self.order_reference_number = OrderReferenceNumber(data, current, self)
        if not self.order_reference_number.valid:
            self._error = self.order_reference_number._error
            return

        current += self.order_reference_number.length

        self.buy_sell_indicator = BuySellIndicator(data, current, self)
        if not self.buy_sell_indicator.valid:
            self._error = self.buy_sell_indicator._error
            return

        current += self.buy_sell_indicator.length

        self.shares = Shares(data, current, self)
        if not self.shares.valid:
            self._error = self.shares._error
            return

        current += self.shares.length

        self.stock = Stock(data, current, self)
        if not self.stock.valid:
            self._error = self.stock._error
            return

        current += self.stock.length

        self.price = Price(data, current, self)
        if not self.price.valid:
            self._error = self.price._error
            return

        current += self.price.length

        self._length = current - offset

    @property
    def valid(self) -> bool:
        return self._error is None

class OperationalHaltMessage:
    __slots__ = ('_name', '_error', '_length', '_parent', 'stock_locate', 'tracking_number', 'timestamp', 'stock', 'market_code', 'operational_halt_action')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Operational Halt Message"
        self._error = None
        self._length = 0
        self._parent = parent
        self.stock_locate = None
        self.tracking_number = None
        self.timestamp = None
        self.stock = None
        self.market_code = None
        self.operational_halt_action = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        current = offset

        self.stock_locate = StockLocate(data, current, self)
        if not self.stock_locate.valid:
            self._error = self.stock_locate._error
            return

        current += self.stock_locate.length

        self.tracking_number = TrackingNumber(data, current, self)
        if not self.tracking_number.valid:
            self._error = self.tracking_number._error
            return

        current += self.tracking_number.length

        self.timestamp = Timestamp(data, current, self)
        if not self.timestamp.valid:
            self._error = self.timestamp._error
            return

        current += self.timestamp.length

        self.stock = Stock(data, current, self)
        if not self.stock.valid:
            self._error = self.stock._error
            return

        current += self.stock.length

        self.market_code = MarketCode(data, current, self)
        if not self.market_code.valid:
            self._error = self.market_code._error
            return

        current += self.market_code.length

        self.operational_halt_action = OperationalHaltAction(data, current, self)
        if not self.operational_halt_action.valid:
            self._error = self.operational_halt_action._error
            return

        current += self.operational_halt_action.length

        self._length = current - offset

    @property
    def valid(self) -> bool:
        return self._error is None

class LuldAuctionCollarMessage:
    __slots__ = ('_name', '_error', '_length', '_parent', 'stock_locate', 'tracking_number', 'timestamp', 'stock', 'auction_collar_reference_price', 'upper_auction_collar_price', 'lower_auction_collar_price', 'auction_collar_extension')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Luld Auction Collar Message"
        self._error = None
        self._length = 0
        self._parent = parent
        self.stock_locate = None
        self.tracking_number = None
        self.timestamp = None
        self.stock = None
        self.auction_collar_reference_price = None
        self.upper_auction_collar_price = None
        self.lower_auction_collar_price = None
        self.auction_collar_extension = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        current = offset

        self.stock_locate = StockLocate(data, current, self)
        if not self.stock_locate.valid:
            self._error = self.stock_locate._error
            return

        current += self.stock_locate.length

        self.tracking_number = TrackingNumber(data, current, self)
        if not self.tracking_number.valid:
            self._error = self.tracking_number._error
            return

        current += self.tracking_number.length

        self.timestamp = Timestamp(data, current, self)
        if not self.timestamp.valid:
            self._error = self.timestamp._error
            return

        current += self.timestamp.length

        self.stock = Stock(data, current, self)
        if not self.stock.valid:
            self._error = self.stock._error
            return

        current += self.stock.length

        self.auction_collar_reference_price = AuctionCollarReferencePrice(data, current, self)
        if not self.auction_collar_reference_price.valid:
            self._error = self.auction_collar_reference_price._error
            return

        current += self.auction_collar_reference_price.length

        self.upper_auction_collar_price = UpperAuctionCollarPrice(data, current, self)
        if not self.upper_auction_collar_price.valid:
            self._error = self.upper_auction_collar_price._error
            return

        current += self.upper_auction_collar_price.length

        self.lower_auction_collar_price = LowerAuctionCollarPrice(data, current, self)
        if not self.lower_auction_collar_price.valid:
            self._error = self.lower_auction_collar_price._error
            return

        current += self.lower_auction_collar_price.length

        self.auction_collar_extension = AuctionCollarExtension(data, current, self)
        if not self.auction_collar_extension.valid:
            self._error = self.auction_collar_extension._error
            return

        current += self.auction_collar_extension.length

        self._length = current - offset

    @property
    def valid(self) -> bool:
        return self._error is None

class IpoQuotingPeriodUpdate:
    __slots__ = ('_name', '_error', '_length', '_parent', 'stock_locate', 'tracking_number', 'timestamp', 'stock', 'ipo_quotation_release_time', 'ipo_quotation_release_qualifier', 'ipo_price')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Ipo Quoting Period Update"
        self._error = None
        self._length = 0
        self._parent = parent
        self.stock_locate = None
        self.tracking_number = None
        self.timestamp = None
        self.stock = None
        self.ipo_quotation_release_time = None
        self.ipo_quotation_release_qualifier = None
        self.ipo_price = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        current = offset

        self.stock_locate = StockLocate(data, current, self)
        if not self.stock_locate.valid:
            self._error = self.stock_locate._error
            return

        current += self.stock_locate.length

        self.tracking_number = TrackingNumber(data, current, self)
        if not self.tracking_number.valid:
            self._error = self.tracking_number._error
            return

        current += self.tracking_number.length

        self.timestamp = Timestamp(data, current, self)
        if not self.timestamp.valid:
            self._error = self.timestamp._error
            return

        current += self.timestamp.length

        self.stock = Stock(data, current, self)
        if not self.stock.valid:
            self._error = self.stock._error
            return

        current += self.stock.length

        self.ipo_quotation_release_time = IpoQuotationReleaseTime(data, current, self)
        if not self.ipo_quotation_release_time.valid:
            self._error = self.ipo_quotation_release_time._error
            return

        current += self.ipo_quotation_release_time.length

        self.ipo_quotation_release_qualifier = IpoQuotationReleaseQualifier(data, current, self)
        if not self.ipo_quotation_release_qualifier.valid:
            self._error = self.ipo_quotation_release_qualifier._error
            return

        current += self.ipo_quotation_release_qualifier.length

        self.ipo_price = IpoPrice(data, current, self)
        if not self.ipo_price.valid:
            self._error = self.ipo_price._error
            return

        current += self.ipo_price.length

        self._length = current - offset

    @property
    def valid(self) -> bool:
        return self._error is None

class MwcbStatusLevelMessage:
    __slots__ = ('_name', '_error', '_length', '_parent', 'stock_locate', 'tracking_number', 'timestamp', 'breached_level')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Mwcb Status Level Message"
        self._error = None
        self._length = 0
        self._parent = parent
        self.stock_locate = None
        self.tracking_number = None
        self.timestamp = None
        self.breached_level = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        current = offset

        self.stock_locate = StockLocate(data, current, self)
        if not self.stock_locate.valid:
            self._error = self.stock_locate._error
            return

        current += self.stock_locate.length

        self.tracking_number = TrackingNumber(data, current, self)
        if not self.tracking_number.valid:
            self._error = self.tracking_number._error
            return

        current += self.tracking_number.length

        self.timestamp = Timestamp(data, current, self)
        if not self.timestamp.valid:
            self._error = self.timestamp._error
            return

        current += self.timestamp.length

        self.breached_level = BreachedLevel(data, current, self)
        if not self.breached_level.valid:
            self._error = self.breached_level._error
            return

        current += self.breached_level.length

        self._length = current - offset

    @property
    def valid(self) -> bool:
        return self._error is None

class MwcbDeclineLevelMessage:
    __slots__ = ('_name', '_error', '_length', '_parent', 'stock_locate', 'tracking_number', 'timestamp', 'level_1', 'level_2', 'level_3')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Mwcb Decline Level Message"
        self._error = None
        self._length = 0
        self._parent = parent
        self.stock_locate = None
        self.tracking_number = None
        self.timestamp = None
        self.level_1 = None
        self.level_2 = None
        self.level_3 = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        current = offset

        self.stock_locate = StockLocate(data, current, self)
        if not self.stock_locate.valid:
            self._error = self.stock_locate._error
            return

        current += self.stock_locate.length

        self.tracking_number = TrackingNumber(data, current, self)
        if not self.tracking_number.valid:
            self._error = self.tracking_number._error
            return

        current += self.tracking_number.length

        self.timestamp = Timestamp(data, current, self)
        if not self.timestamp.valid:
            self._error = self.timestamp._error
            return

        current += self.timestamp.length

        self.level_1 = Level1(data, current, self)
        if not self.level_1.valid:
            self._error = self.level_1._error
            return

        current += self.level_1.length

        self.level_2 = Level2(data, current, self)
        if not self.level_2.valid:
            self._error = self.level_2._error
            return

        current += self.level_2.length

        self.level_3 = Level3(data, current, self)
        if not self.level_3.valid:
            self._error = self.level_3._error
            return

        current += self.level_3.length

        self._length = current - offset

    @property
    def valid(self) -> bool:
        return self._error is None

class MarketParticipantPositionMessage:
    __slots__ = ('_name', '_error', '_length', '_parent', 'stock_locate', 'tracking_number', 'timestamp', 'mpid', 'stock', 'primary_market_maker', 'market_maker_mode', 'market_participant_state')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Market Participant Position Message"
        self._error = None
        self._length = 0
        self._parent = parent
        self.stock_locate = None
        self.tracking_number = None
        self.timestamp = None
        self.mpid = None
        self.stock = None
        self.primary_market_maker = None
        self.market_maker_mode = None
        self.market_participant_state = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        current = offset

        self.stock_locate = StockLocate(data, current, self)
        if not self.stock_locate.valid:
            self._error = self.stock_locate._error
            return

        current += self.stock_locate.length

        self.tracking_number = TrackingNumber(data, current, self)
        if not self.tracking_number.valid:
            self._error = self.tracking_number._error
            return

        current += self.tracking_number.length

        self.timestamp = Timestamp(data, current, self)
        if not self.timestamp.valid:
            self._error = self.timestamp._error
            return

        current += self.timestamp.length

        self.mpid = Mpid(data, current, self)
        if not self.mpid.valid:
            self._error = self.mpid._error
            return

        current += self.mpid.length

        self.stock = Stock(data, current, self)
        if not self.stock.valid:
            self._error = self.stock._error
            return

        current += self.stock.length

        self.primary_market_maker = PrimaryMarketMaker(data, current, self)
        if not self.primary_market_maker.valid:
            self._error = self.primary_market_maker._error
            return

        current += self.primary_market_maker.length

        self.market_maker_mode = MarketMakerMode(data, current, self)
        if not self.market_maker_mode.valid:
            self._error = self.market_maker_mode._error
            return

        current += self.market_maker_mode.length

        self.market_participant_state = MarketParticipantState(data, current, self)
        if not self.market_participant_state.valid:
            self._error = self.market_participant_state._error
            return

        current += self.market_participant_state.length

        self._length = current - offset

    @property
    def valid(self) -> bool:
        return self._error is None

class RegShoShortSalePriceTestRestrictedIndicatorMessage:
    __slots__ = ('_name', '_error', '_length', '_parent', 'locate_code', 'tracking_number', 'timestamp', 'stock', 'reg_sho_action')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Reg Sho Short Sale Price Test Restricted Indicator Message"
        self._error = None
        self._length = 0
        self._parent = parent
        self.locate_code = None
        self.tracking_number = None
        self.timestamp = None
        self.stock = None
        self.reg_sho_action = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        current = offset

        self.locate_code = LocateCode(data, current, self)
        if not self.locate_code.valid:
            self._error = self.locate_code._error
            return

        current += self.locate_code.length

        self.tracking_number = TrackingNumber(data, current, self)
        if not self.tracking_number.valid:
            self._error = self.tracking_number._error
            return

        current += self.tracking_number.length

        self.timestamp = Timestamp(data, current, self)
        if not self.timestamp.valid:
            self._error = self.timestamp._error
            return

        current += self.timestamp.length

        self.stock = Stock(data, current, self)
        if not self.stock.valid:
            self._error = self.stock._error
            return

        current += self.stock.length

        self.reg_sho_action = RegShoAction(data, current, self)
        if not self.reg_sho_action.valid:
            self._error = self.reg_sho_action._error
            return

        current += self.reg_sho_action.length

        self._length = current - offset

    @property
    def valid(self) -> bool:
        return self._error is None

class StockTradingActionMessage:
    __slots__ = ('_name', '_error', '_length', '_parent', 'stock_locate', 'tracking_number', 'timestamp', 'stock', 'trading_state', 'reserved', 'reason_code')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Stock Trading Action Message"
        self._error = None
        self._length = 0
        self._parent = parent
        self.stock_locate = None
        self.tracking_number = None
        self.timestamp = None
        self.stock = None
        self.trading_state = None
        self.reserved = None
        self.reason_code = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        current = offset

        self.stock_locate = StockLocate(data, current, self)
        if not self.stock_locate.valid:
            self._error = self.stock_locate._error
            return

        current += self.stock_locate.length

        self.tracking_number = TrackingNumber(data, current, self)
        if not self.tracking_number.valid:
            self._error = self.tracking_number._error
            return

        current += self.tracking_number.length

        self.timestamp = Timestamp(data, current, self)
        if not self.timestamp.valid:
            self._error = self.timestamp._error
            return

        current += self.timestamp.length

        self.stock = Stock(data, current, self)
        if not self.stock.valid:
            self._error = self.stock._error
            return

        current += self.stock.length

        self.trading_state = TradingState(data, current, self)
        if not self.trading_state.valid:
            self._error = self.trading_state._error
            return

        current += self.trading_state.length

        self.reserved = Reserved(data, current, self)
        if not self.reserved.valid:
            self._error = self.reserved._error
            return

        current += self.reserved.length

        self.reason_code = ReasonCode(data, current, self)
        if not self.reason_code.valid:
            self._error = self.reason_code._error
            return

        current += self.reason_code.length

        self._length = current - offset

    @property
    def valid(self) -> bool:
        return self._error is None

class StockDirectoryMessage:
    __slots__ = ('_name', '_error', '_length', '_parent', 'stock_locate', 'tracking_number', 'timestamp', 'stock', 'market_category', 'financial_status_indicator', 'round_lot_size', 'round_lots_only', 'issue_classification', 'issue_sub_type', 'authenticity', 'short_sale_threshold_indicator', 'ipo_flag', 'luld_reference_price_tier', 'etp_flag', 'etp_leverage_factor', 'inverse_indicator')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Stock Directory Message"
        self._error = None
        self._length = 0
        self._parent = parent
        self.stock_locate = None
        self.tracking_number = None
        self.timestamp = None
        self.stock = None
        self.market_category = None
        self.financial_status_indicator = None
        self.round_lot_size = None
        self.round_lots_only = None
        self.issue_classification = None
        self.issue_sub_type = None
        self.authenticity = None
        self.short_sale_threshold_indicator = None
        self.ipo_flag = None
        self.luld_reference_price_tier = None
        self.etp_flag = None
        self.etp_leverage_factor = None
        self.inverse_indicator = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        current = offset

        self.stock_locate = StockLocate(data, current, self)
        if not self.stock_locate.valid:
            self._error = self.stock_locate._error
            return

        current += self.stock_locate.length

        self.tracking_number = TrackingNumber(data, current, self)
        if not self.tracking_number.valid:
            self._error = self.tracking_number._error
            return

        current += self.tracking_number.length

        self.timestamp = Timestamp(data, current, self)
        if not self.timestamp.valid:
            self._error = self.timestamp._error
            return

        current += self.timestamp.length

        self.stock = Stock(data, current, self)
        if not self.stock.valid:
            self._error = self.stock._error
            return

        current += self.stock.length

        self.market_category = MarketCategory(data, current, self)
        if not self.market_category.valid:
            self._error = self.market_category._error
            return

        current += self.market_category.length

        self.financial_status_indicator = FinancialStatusIndicator(data, current, self)
        if not self.financial_status_indicator.valid:
            self._error = self.financial_status_indicator._error
            return

        current += self.financial_status_indicator.length

        self.round_lot_size = RoundLotSize(data, current, self)
        if not self.round_lot_size.valid:
            self._error = self.round_lot_size._error
            return

        current += self.round_lot_size.length

        self.round_lots_only = RoundLotsOnly(data, current, self)
        if not self.round_lots_only.valid:
            self._error = self.round_lots_only._error
            return

        current += self.round_lots_only.length

        self.issue_classification = IssueClassification(data, current, self)
        if not self.issue_classification.valid:
            self._error = self.issue_classification._error
            return

        current += self.issue_classification.length

        self.issue_sub_type = IssueSubType(data, current, self)
        if not self.issue_sub_type.valid:
            self._error = self.issue_sub_type._error
            return

        current += self.issue_sub_type.length

        self.authenticity = Authenticity(data, current, self)
        if not self.authenticity.valid:
            self._error = self.authenticity._error
            return

        current += self.authenticity.length

        self.short_sale_threshold_indicator = ShortSaleThresholdIndicator(data, current, self)
        if not self.short_sale_threshold_indicator.valid:
            self._error = self.short_sale_threshold_indicator._error
            return

        current += self.short_sale_threshold_indicator.length

        self.ipo_flag = IpoFlag(data, current, self)
        if not self.ipo_flag.valid:
            self._error = self.ipo_flag._error
            return

        current += self.ipo_flag.length

        self.luld_reference_price_tier = LuldReferencePriceTier(data, current, self)
        if not self.luld_reference_price_tier.valid:
            self._error = self.luld_reference_price_tier._error
            return

        current += self.luld_reference_price_tier.length

        self.etp_flag = EtpFlag(data, current, self)
        if not self.etp_flag.valid:
            self._error = self.etp_flag._error
            return

        current += self.etp_flag.length

        self.etp_leverage_factor = EtpLeverageFactor(data, current, self)
        if not self.etp_leverage_factor.valid:
            self._error = self.etp_leverage_factor._error
            return

        current += self.etp_leverage_factor.length

        self.inverse_indicator = InverseIndicator(data, current, self)
        if not self.inverse_indicator.valid:
            self._error = self.inverse_indicator._error
            return

        current += self.inverse_indicator.length

        self._length = current - offset

    @property
    def valid(self) -> bool:
        return self._error is None

class SystemEventMessage:
    __slots__ = ('_name', '_error', '_length', '_parent', 'stock_locate', 'tracking_number', 'timestamp', 'event_code')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "System Event Message"
        self._error = None
        self._length = 0
        self._parent = parent
        self.stock_locate = None
        self.tracking_number = None
        self.timestamp = None
        self.event_code = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        current = offset

        self.stock_locate = StockLocate(data, current, self)
        if not self.stock_locate.valid:
            self._error = self.stock_locate._error
            return

        current += self.stock_locate.length

        self.tracking_number = TrackingNumber(data, current, self)
        if not self.tracking_number.valid:
            self._error = self.tracking_number._error
            return

        current += self.tracking_number.length

        self.timestamp = Timestamp(data, current, self)
        if not self.timestamp.valid:
            self._error = self.timestamp._error
            return

        current += self.timestamp.length

        self.event_code = EventCode(data, current, self)
        if not self.event_code.valid:
            self._error = self.event_code._error
            return

        current += self.event_code.length

        self._length = current - offset

    @property
    def valid(self) -> bool:
        return self._error is None

def Payload_factory(data: bytes, offset: int, parent, message_type):
    """TODO"""
    match message_type:
        case "S":
            return SystemEventMessage(data, offset, parent)

        case "R":
            return StockDirectoryMessage(data, offset, parent)

        case "H":
            return StockTradingActionMessage(data, offset, parent)

        case "Y":
            return RegShoShortSalePriceTestRestrictedIndicatorMessage(data, offset, parent)

        case "L":
            return MarketParticipantPositionMessage(data, offset, parent)

        case "V":
            return MwcbDeclineLevelMessage(data, offset, parent)

        case "W":
            return MwcbStatusLevelMessage(data, offset, parent)

        case "K":
            return IpoQuotingPeriodUpdate(data, offset, parent)

        case "J":
            return LuldAuctionCollarMessage(data, offset, parent)

        case "h":
            return OperationalHaltMessage(data, offset, parent)

        case "A":
            return AddOrderNoMpidAttributionMessage(data, offset, parent)

        case "F":
            return AddOrderWithMpidAttributionMessage(data, offset, parent)

        case "E":
            return OrderExecutedMessage(data, offset, parent)

        case "C":
            return OrderExecutedWithPriceMessage(data, offset, parent)

        case "X":
            return OrderCancelMessage(data, offset, parent)

        case "D":
            return OrderDeleteMessage(data, offset, parent)

        case "U":
            return OrderReplaceMessage(data, offset, parent)

        case "P":
            return NonCrossTradeMessage(data, offset, parent)

        case "Q":
            return CrossTradeMessage(data, offset, parent)

        case "B":
            return BrokenTradeMessage(data, offset, parent)

        case "I":
            return NetOrderImbalanceIndicatorMessage(data, offset, parent)

        case "N":
            return RetailPriceImprovementIndicatorMessage(data, offset, parent)

        case "O":
            return DirectListingWithCapitalRaisePriceDiscoveryMessage(data, offset, parent)

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
    __slots__ = ('_name', '_error', '_length', '_parent', 'message_header', 'payload')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Message"
        self._error = None
        self._length = 0
        self._parent = parent
        self.message_header = None
        self.payload = None

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
        self.payload = Payload_factory(data, current, self, message_type)
        if not self.payload.valid:
            self._error = self.payload._error
            return

        current += self.payload._length

        self._length = current - offset

    @property
    def valid(self) -> bool:
        return self._error is None

class PacketHeader:
    __slots__ = ('_name', '_error', '_length', '_parent', 'session', 'sequence_number', 'message_count')

    def __init__(self, data: bytes, offset: int, parent) -> None:
        self._name = "Packet Header"
        self._error = None
        self._length = 0
        self._parent = parent
        self.session = None
        self.sequence_number = None
        self.message_count = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        if not isinstance(offset, int):
            self._error = f"Unexpected 'offset' type: {type(offset)}"
            return

        current = offset

        self.session = Session(data, current, self)
        if not self.session.valid:
            self._error = self.session._error
            return

        current += self.session.length

        self.sequence_number = SequenceNumber(data, current, self)
        if not self.sequence_number.valid:
            self._error = self.sequence_number._error
            return

        current += self.sequence_number.length

        self.message_count = MessageCount(data, current, self)
        if not self.message_count.valid:
            self._error = self.message_count._error
            return

        current += self.message_count.length

        self._length = current - offset

    @property
    def valid(self) -> bool:
        return self._error is None

class Packet:
    __slots__ = ('_name', '_error', 'packet_header', 'messages')

    def __init__(self, data: bytes) -> None:
        self._name = "Packet"
        self._error = None
        self.packet_header = None
        self.messages = None

        if not isinstance(data, bytes):
            self._error = f"Unexpected 'data' type: {type(data)}"
            return

        current = 0

        self.packet_header = PacketHeader(data, current, self)
        if not self.packet_header.valid:
            self._error = self.packet_header._error
            return

        current += self.packet_header._length

        self.messages = []
        _count = self.packet_header.message_count.value

        if _count == 0:
            return

        if _count == 65535:
            return


        for _ in range(_count):
            message = Message(data, current, self)
            if not message.valid:
                self._error = message._error
                return

            self.messages.append(message)
            current += message._length

    @property
    def valid(self) -> bool:
        return self._error is None

