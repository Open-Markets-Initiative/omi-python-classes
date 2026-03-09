# Omi Python Parsers

[![Python](https://github.com/Open-Markets-Initiative/Directory/blob/main/About/Images/Python.png)](https://www.python.org)

Omi Python parsers provide generated binary protocol decoders for common exchange protocols.

## Usage

Install the package:

```
pip install omipy
```
Parse a pcap file:

```
from omipy.iex.equities.tops.v1_6_6 import Iex

for packet in Iex.packets("path/to/file.pcap"):
    for message in packet.messages:
        print(message.message_data._name)
```
## Development

Updates are greatly appreciated; however, this entire repository is source generated. If you wish to suggest updates, the recommended process is to create an issue with changes and explanation.

| Protocol Count | Generated Lines |
| --- | --- |
| 7 | 26,392 |

## Testing

Please report any parsing errors as an [issue](https://github.com/Open-Markets-Initiative/omi-python-parsers/issues "Omi Python Parsers Issues").  Include a small note on the protocol and version, and a minimal capture demonstrating the problem.

## Open Markets Initiative

[![Omi](https://github.com/Open-Markets-Initiative/Directory/blob/main/About/Images/Logo.png)](https://github.com/Open-Markets-Initiative/Directory)  The Open Markets Initiative (Omi) is a group of technologists dedicated to enhancing the stability of electronic financial markets using modern development methods.

For a list of Omi Hft projects: [Omi Projects](https://github.com/Open-Markets-Initiative/Directory/tree/main/Projects "Open Markets Initiative Projects")

For details of Omi rules and regulations: [Omi Directory](https://github.com/Open-Markets-Initiative/Directory "Open Markets Initiative Directory")
## Protocols

Parsers by exchange: [Iex][Iex.Directory], [Nasdaq][Nasdaq.Directory]

## Disclaimer

Any similarities between existing people, places and/or protocols is purely incidental.

Enjoy.

[Omi Projects]: https://github.com/Open-Markets-Initiative/Directory/tree/main/Projects "Open Markets Initiative Projects"
[Omi Rules and Regulations]: https://github.com/Open-Markets-Initiative/Directory/tree/main/License "Open Markets Initiative Rules and Regulations"

[Omi.Glossary.Testing]: https://github.com/Open-Markets-Initiative/Directory/blob/main/Glossary/Testing.md "Protocol Testing Status"
[Omi.Glossary.Testing.Verified]: https://github.com/Open-Markets-Initiative/Directory/blob/main/Glossary/Testing.md "Testing Status: Protocol has been tested on live data"
[Omi.Glossary.Testing.Incomplete]: https://github.com/Open-Markets-Initiative/Directory/blob/main/Glossary/Testing.md "Testing Status: Protocol has been tested on live data but contains known issues"
[Omi.Glossary.Testing.Beta]: https://github.com/Open-Markets-Initiative/Directory/blob/main/Glossary/Testing.md "Testing Status: Protocol has not been tested and structure is speculative"
[Omi.Glossary.Testing.Untested]: https://github.com/Open-Markets-Initiative/Directory/blob/main/Glossary/Testing.md "Testing Status: Protocol has not been tested on live data"

[Iex.Directory]: https://github.com/Open-Markets-Initiative/omi-python-parsers/tree/main/Iex "Investors Exchange"
[Nasdaq.Directory]: https://github.com/Open-Markets-Initiative/omi-python-parsers/tree/main/Nasdaq "National Association of Securities Dealers Automated Quotations"
