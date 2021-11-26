# Pkt-Krafter

A small library to create your own packets for testing.


The packet class includes methods of adding layers to the packet.

The following example illustrates the usage

```python
import pktKrafter as pk


sample_packet = pk.Packet()
simple_udp_packet = sample_packet.create_udp_packet()
sample_packet.send_simple_ip_packet(simple_udp_packet)

```
