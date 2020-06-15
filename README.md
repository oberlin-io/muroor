# muroor
Experimenting with extracting network packet capture fields
and transforming them into a feature vector space for modeling.

This also considers sample size and rate
as well as appending samples to the master vector space file
and limiting its size (in effect prepending newest sample batch
and deleting appropriate number of tail rows).

Probably best to make use of Scapy for packet capture,
instead of recreating extraction.
https://0xbharath.github.io/art-of-packet-crafting-with-scapy/scapy/sniffing/index.html

Check for ease of integrating in capture -> transform -> vector space.
