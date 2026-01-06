# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Jack Winch <jack.winch@bitryx.io>

# scapy.contrib.description = AUTOSAR Time Synchronization over CAN
# scapy.contrib.status = loads

"""
AUTOSAR Time Synchronization over CAN

This module implements time synchronization message formats for CAN and CAN FD.
Messages are multiplexed on the same CAN identifier using the Type field.

General Rules:
- Byte order: Big Endian for time value signals
- DLC: 8 bytes for classic CAN, 16 bytes for CAN FD (extended format)
- Type field at Byte 0 acts as multiplexer

Message Types (no CRC, CRC secured):
- SYNC (0x10, 0x20): Synchronization message with seconds timestamp
- FUP (0x18, 0x28): Follow-up message with nanoseconds timestamp
- OFS (0x34, 0x44, 0x54, 0x64): Offset message with seconds timestamp
- OFNS (0x3C, 0x4C): Offset message with nanoseconds timestamp

Usage:
    from scapy.layers.can import CAN, CANFD
    from scapy.contrib.automotive.autosar.tsyn_can import (
        Base, Sync, FollowUp, SyncWithCrc, FollowUpWithCrc,
        Offset, OffsetNanoseconds, OffsetWithCrc, OffsetNanosecondsWithCrc,
        OffsetExtended, OffsetExtendedWithCrc
    )

    # Build a SYNC message
    sync_msg = Base(type=0x10) / Sync(
        time_domain=1,
        seq_counter=5,
        sync_time_sec=1234567890
    )

    # Create CAN frame with Tsyn message
    can_frame = CAN(identifier=0x200, data=bytes(sync_msg))

    # Parse raw Tsyn data
    raw_data = b'\x10\x00\x15\x00\x49\x96\x02\xD2'
    parsed = Base(raw_data)

    # For automatic dissection with bind_layers, users can bind
    # Base to interpret the data field of specific CAN identifiers:
    # Note: Due to how Scapy's CAN layer works, the data field won't
    # automatically dissect into layers. Users should manually parse:
    tsyn_msg = Base(can_pkt.data)
"""

from scapy.fields import (
    BitField,
    ByteField,
    IntField,
    XByteField,
    XShortField,
)
from scapy.layers.can import CAN, CANFD
from scapy.packet import Packet

class Base(Packet):
    """
    AUTOSAR Time Synchronization over CAN base layer

    This packet uses the Type field to determine the actual message format.
    It will automatically dispatch to the appropriate message class.
    """
    name = "AUTOSAR Tsyn CAN"

    fields_desc = [
        ByteField("type", 0x10),
    ]

    def guess_payload_class(self, payload):
        """Dispatch to specific message type based on Type field"""
        type_map = {
            0x10: Sync,
            0x18: FollowUp,
            0x20: SyncWithCrc,
            0x28: FollowUpWithCrc,
            0x34: Offset,
            0x3C: OffsetNanoseconds,
            0x44: OffsetWithCrc,
            0x4C: OffsetNanosecondsWithCrc,
            0x54: OffsetExtended,
            0x64: OffsetExtendedWithCrc,
        }
        return type_map.get(self.type, Packet.guess_payload_class(self, payload))


class Sync(Packet):
    """
    SYNC Message - Not CRC Secured (Type 0x10)
    """
    name = "AUTOSAR Tsyn CAN SYNC"

    fields_desc = [
        XByteField("user_byte_1", 0),
        BitField("time_domain", 0, 4),
        BitField("seq_counter", 0, 4),
        XByteField("user_byte_0", 0),
        IntField("sync_time_sec", 0),
    ]


class FollowUp(Packet):
    """
    FUP (Follow-Up) Message - Not CRC Secured (Type 0x18)
    """
    name = "AUTOSAR Tsyn CANFUP"

    fields_desc = [
        XByteField("user_byte_2", 0),
        BitField("time_domain", 0, 4),
        BitField("seq_counter", 0, 4),
        BitField("reserved", 0, 5),
        BitField("sgw", 0, 1),
        BitField("ovs", 0, 2),
        IntField("sync_time_nsec", 0),
    ]


class SyncWithCrc(Packet):
    """
    SYNC Message - CRC Secured (Type 0x20)
    """
    name = "AUTOSAR Tsyn CAN SYNC CRC"

    fields_desc = [
        XByteField("crc", 0),
        BitField("time_domain", 0, 4),
        BitField("seq_counter", 0, 4),
        XByteField("user_byte_0", 0),
        IntField("sync_time_sec", 0),
    ]


class FollowUpWithCrc(Packet):
    """
    FUP (Follow-Up) Message - CRC Secured (Type 0x28)
    """
    name = "AUTOSAR Tsyn CAN FUP CRC"

    fields_desc = [
        XByteField("crc", 0),
        BitField("time_domain", 0, 4),
        BitField("seq_counter", 0, 4),
        BitField("reserved", 0, 5),
        BitField("sgw", 0, 1),
        BitField("ovs", 0, 2),
        IntField("sync_time_nsec", 0),
    ]


class Offset(Packet):
    """
    OFS (Offset) Message - Not CRC Secured (Type 0x34)
    """
    name = "AUTOSAR Tsyn CAN OFS"

    fields_desc = [
        XByteField("user_byte_1", 0),
        BitField("time_domain", 0, 4),
        BitField("seq_counter", 0, 4),
        XByteField("user_byte_0", 0),
        IntField("ofs_time_sec", 0),
    ]


class OffsetNanoseconds(Packet):
    """
    OFNS (Offset Nanoseconds) Message - Not CRC Secured (Type 0x3C)
    """
    name = "AUTOSAR Tsyn CAN OFNS"

    fields_desc = [
        XByteField("user_byte_2", 0),
        BitField("time_domain", 0, 4),
        BitField("seq_counter", 0, 4),
        BitField("reserved", 0, 7),
        BitField("sgw", 0, 1),
        IntField("ofs_time_nsec", 0),
    ]


class OffsetWithCrc(Packet):
    """
    OFS (Offset) Message - CRC Secured (Type 0x44)
    """
    name = "AUTOSAR Tsyn CAN OFS CRC"

    fields_desc = [
        XByteField("crc", 0),
        BitField("time_domain", 0, 4),
        BitField("seq_counter", 0, 4),
        XByteField("user_byte_0", 0),
        IntField("ofs_time_sec", 0),
    ]


class OffsetNanosecondsWithCrc(Packet):
    """
    OFNS (Offset Nanoseconds) Message - CRC Secured (Type 0x4C)
    """
    name = "AUTOSAR Tsyn CAN OFNS CRC"

    fields_desc = [
        XByteField("crc", 0),
        BitField("time_domain", 0, 4),
        BitField("seq_counter", 0, 4),
        BitField("reserved", 0, 7),
        BitField("sgw", 0, 1),
        IntField("ofs_time_nsec", 0),
    ]


class OffsetExtended(Packet):
    """
    OFS Extended Message - Not CRC Secured (Type 0x54)
    """
    name = "AUTOSAR Tsyn CAN OFS Extended"

    fields_desc = [
        XByteField("user_byte_2", 0),
        BitField("time_domain", 0, 4),
        BitField("seq_counter", 0, 4),
        BitField("reserved1", 0, 7),
        BitField("sgw", 0, 1),
        XByteField("user_byte_0", 0),
        XByteField("user_byte_1", 0),
        XShortField("reserved2", 0),
        IntField("ofs_time_sec", 0),
        IntField("ofs_time_nsec", 0),
    ]


class OffsetExtendedWithCrc(Packet):
    """
    OFS Extended Message - CRC Secured (Type 0x64)
    """
    name = "AUTOSAR Tsyn CAN OFS Extended CRC"

    fields_desc = [
        XByteField("crc", 0),
        BitField("time_domain", 0, 4),
        BitField("seq_counter", 0, 4),
        BitField("reserved1", 0, 7),
        BitField("sgw", 0, 1),
        XByteField("user_byte_0", 0),
        XByteField("user_byte_1", 0),
        XShortField("reserved2", 0),
        IntField("ofs_time_sec", 0),
        IntField("ofs_time_nsec", 0),
    ]
