# SPDX-License-Identifier: GPL-2.0-or-later
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Michael Farrell <micolous+git@gmail.com>

# scapy.contrib.description = iBeacon BLE proximity beacon
# scapy.contrib.status = loads
"""
scapy.contrib.ibeacon - Apple iBeacon Bluetooth LE proximity beacons.

Packet format documentation can be found at at:

* https://en.wikipedia.org/wiki/IBeacon#Packet_Structure_Byte_Map (public)
* https://developer.apple.com/ibeacon/ (official, requires license)

"""

from scapy.fields import ByteEnumField, ConditionalField, LenField, PacketListField, ShortField, SignedByteField, UUIDField
from scapy.layers.bluetooth import EIR_Hdr, EIR_Manufacturer_Specific_Data, LowEnergyBeaconHelper
from scapy.packet import bind_layers, Packet

APPLE_MFG = 0x004C


class Apple_BLE_Submessage(Packet, LowEnergyBeaconHelper):
    """
    A basic Apple submessage.
    """

    name = 'Apple BLE submessage'
    fields_desc = [
        ByteEnumField(
            'subtype',
            None,
            {
                0x01: 'overflow',
                0x02: 'ibeacon',
                0x05: 'airdrop',
                0x07: 'airpods',
                0x09: 'airplay_sink',
                0x0A: 'airplay_src',
                0x0C: 'handoff',
                0x10: 'nearby',
            },
        ),
        ConditionalField(
            # "overflow" messages omit `len` field
            LenField('len', None, fmt='B'),
            lambda pkt: pkt.subtype != 0x01,
        ),
    ]

    def extract_padding(self, s):
        # Needed to end each EIR_Element packet and make PacketListField work.
        if self.subtype == 0x01:
            # Overflow messages are always 16 bytes.
            return s[:16], s[16:]
        return s[: self.len], s[self.len :]

    # These methods are here in case you only want to send 1 submessage.
    # It creates an Apple_BLE_Frame to wrap your (single) Apple_BLE_Submessage.
    def build_frame(self):
        """Wraps this submessage in a Apple_BLE_Frame."""
        return Apple_BLE_Frame(plist=[self])

    def build_eir(self):
        """See Apple_BLE_Frame.build_eir."""
        return self.build_frame().build_eir()


class Apple_BLE_Frame(Packet, LowEnergyBeaconHelper):
    """
    The wrapper for a BLE manufacturer-specific data advertisement from Apple
    devices.

    Each advertisement is composed of one or multiple submessages.

    The length of this field comes from the EIR_Hdr.
    """

    name = 'Apple BLE broadcast frame'
    fields_desc = [PacketListField('plist', None, Apple_BLE_Submessage)]

    def build_eir(self):
        """Builds a list of EIR messages to wrap this frame."""

        return LowEnergyBeaconHelper.base_eir + [EIR_Hdr() / EIR_Manufacturer_Specific_Data() / self]


class IBeacon_Data(Packet):
    """
    iBeacon broadcast data frame. Composed on top of an Apple_BLE_Submessage.
    """

    name = 'iBeacon data'
    fields_desc = [
        UUIDField('uuid', None, uuid_fmt=UUIDField.FORMAT_BE),
        ShortField('major', None),
        ShortField('minor', None),
        SignedByteField('tx_power', None),
    ]


bind_layers(EIR_Manufacturer_Specific_Data, Apple_BLE_Frame, company_id=APPLE_MFG)
bind_layers(Apple_BLE_Submessage, IBeacon_Data, subtype=2)
