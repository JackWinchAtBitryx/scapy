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
    from scapy.contrib.automotive.autosar.tsyn_can import TSynCanBase

    # Build a SYNC message
    sync_msg = TSynCanBase(type=0x10) / Sync(
        time_domain=1,
        seq_counter=5,
        sync_time_sec=1234567890
    )

    # Create CAN frame with Tsyn message
    can_frame = CAN(identifier=0x200, data=bytes(sync_msg))

    # Parse CAN frame with Tsyn message
    tsyn_msg = TSynCanBase(can_frame.data)

    # Access common fields without haslayer() checks using properties
    domain = tsyn_msg.time_domain  # Works for all message types
    counter = tsyn_msg.seq_counter  # Works for all message types
    crc_val = tsyn_msg.crc  # Returns None if not CRC-secured

    # Check message type using helper methods
    if tsyn_msg.is_sync_message():
        seconds = tsyn_msg.payload.sync_time_sec
        print(f"SYNC message: domain={domain}, time={seconds}s")
    elif tsyn_msg.is_followup_message():
        nanoseconds = tsyn_msg.payload.sync_time_nsec
        print(f"FUP message: domain={domain}, time={nanoseconds}ns")

    # Alternative: Access type-specific fields explicitly
    if tsyn_msg.type == 0x10:
        sync_time = tsyn_msg.payload.sync_time_sec
    elif tsyn_msg.type == 0x18:
        sync_time_ns = tsyn_msg.payload.sync_time_nsec

    # Get human-readable message type name
    msg_type = tsyn_msg.get_message_type_name()  # Returns "SYNC", "FUP_CRC", etc.

CAN FD Extended Message Format (CanTSynUseExtendedMsgFormat):
    Some OEM implementations use 16-byte CAN FD frames for 8-byte messages.
    This matches the AUTOSAR CanTSynUseExtendedMsgFormat configuration parameter.

    Global configuration (affects all TSynCan messages):
        >>> from scapy.config import conf
        >>> conf.contribs['AUTOSAR']['CanTSynUseExtendedMsgFormat'] = True
        >>> msg = TSynCanBase(type=0x10) / Sync(time_domain=1)
        >>> len(bytes(msg))
        16

    Per-packet configuration (set before building):
        >>> msg = TSynCanBase(type=0x10) / Sync(time_domain=1)
        >>> msg.use_extended_msg_format = True
        >>> len(bytes(msg))
        16

    Note: For runtime control of already-built packets, use the global config.

    Parsing automatically handles both 8-byte and 16-byte frames:
        >>> pkt1 = TSynCanBase(b'\\x10\\x00\\x15\\x00\\x49\\x96\\x02\\xd2')  # 8 bytes
        >>> pkt2 = TSynCanBase(b'\\x10\\x00\\x15\\x00\\x49\\x96\\x02\\xd2' + b'\\x00' * 8)  # 16 bytes
        >>> pkt1.time_domain == pkt2.time_domain
        True
"""

from scapy.config import conf
from scapy.contrib.automotive.autosar.tsyn.common import (
    MESSAGE_TYPE_SYNC,
    MESSAGE_TYPE_SYNC_CRC,
    MESSAGE_TYPE_OFS,
    MESSAGE_TYPE_OFS_CRC,
    TSynPropertyAccessorsMixin,
)
from scapy.fields import (
    BitField,
    ByteField,
    IntField,
    XByteField,
    XShortField,
)
from scapy.layers.can import CAN, CANFD
from scapy.packet import Packet

# Initialize AUTOSAR configuration
if 'AUTOSAR' not in conf.contribs:
    conf.contribs['AUTOSAR'] = {}

# CanTSynUseExtendedMsgFormat: Use 16-byte CAN FD frames for 8-byte messages
# Matches AUTOSAR specification parameter name
if 'CanTSynUseExtendedMsgFormat' not in conf.contribs['AUTOSAR']:
    conf.contribs['AUTOSAR']['CanTSynUseExtendedMsgFormat'] = False

# CAN-specific Message Type Constants
# (Shared constants imported from tsyn_common: SYNC, SYNC_CRC, OFS, OFS_CRC)
MESSAGE_TYPE_FUP = 0x18
MESSAGE_TYPE_FUP_CRC = 0x28
MESSAGE_TYPE_OFNS = 0x3C
MESSAGE_TYPE_OFNS_CRC = 0x4C
MESSAGE_TYPE_OFS_EXTENDED = 0x54
MESSAGE_TYPE_OFS_EXTENDED_CRC = 0x64

class TSynCanBase(TSynPropertyAccessorsMixin, Packet):
    """
    AUTOSAR Time Synchronization over CAN base layer

    This packet uses the Type field to determine the actual message format.
    It will automatically dispatch to the appropriate message class.

    Common fields can be accessed via properties without haslayer() checks:
    - time_domain: Available on all message types (from mixin)
    - seq_counter: Available on all message types (from mixin)
    - crc: Only on CRC-secured messages (from mixin)
    - user_byte_0/1/2: Varies by message type (from mixin)
    - sgw: Only on FUP/OFNS/OFS Extended messages (from mixin)
    - ovs: Only on FUP messages (CAN-specific)
    """
    name = "AUTOSAR Tsyn CAN"

    # Per-packet override for CanTSynUseExtendedMsgFormat configuration
    # When True, 8-byte messages are padded to 16 bytes for CAN FD
    use_extended_msg_format = None

    fields_desc = [
        ByteField("type", MESSAGE_TYPE_SYNC),
    ]

    def guess_payload_class(self, payload):
        """Dispatch to specific message type based on Type field"""
        type_map = {
            MESSAGE_TYPE_SYNC: Sync,
            MESSAGE_TYPE_FUP: FollowUp,
            MESSAGE_TYPE_SYNC_CRC: SyncWithCrc,
            MESSAGE_TYPE_FUP_CRC: FollowUpWithCrc,
            MESSAGE_TYPE_OFS: Offset,
            MESSAGE_TYPE_OFNS: OffsetNanoseconds,
            MESSAGE_TYPE_OFS_CRC: OffsetWithCrc,
            MESSAGE_TYPE_OFNS_CRC: OffsetNanosecondsWithCrc,
            MESSAGE_TYPE_OFS_EXTENDED: OffsetExtended,
            MESSAGE_TYPE_OFS_EXTENDED_CRC: OffsetExtendedWithCrc,
        }
        return type_map.get(self.type, Packet.guess_payload_class(self, payload))

    def extract_padding(self, s):
        """
        Extract padding from CAN FD 16-byte frames.

        Handles both 8-byte and 16-byte frames automatically by detecting
        the actual message length based on message type.

        Returns:
            Tuple[bytes, Optional[bytes]]: (data for next layer, padding)
        """
        # Extended OFS messages are always 16 bytes
        if self.type in [MESSAGE_TYPE_OFS_EXTENDED, MESSAGE_TYPE_OFS_EXTENDED_CRC]:
            return s, None

        # 8-byte messages: payload is 7 bytes (type field already consumed)
        elif self.type in [MESSAGE_TYPE_SYNC, MESSAGE_TYPE_FUP, MESSAGE_TYPE_SYNC_CRC,
                           MESSAGE_TYPE_FUP_CRC, MESSAGE_TYPE_OFS, MESSAGE_TYPE_OFNS,
                           MESSAGE_TYPE_OFS_CRC, MESSAGE_TYPE_OFNS_CRC]:
            if len(s) > 7:
                return s[:7], s[7:]  # Return (data, padding)
            return s, None

        # Unknown type, don't strip padding
        return s, None

    def post_build(self, pkt, pay):
        """
        Add CAN FD 16-byte padding if CanTSynUseExtendedMsgFormat is enabled.

        Checks both per-packet attribute and global AUTOSAR config to determine
        if 16-byte padding should be added to 8-byte messages.
        """
        # Determine if we should use extended message format (16-byte padding)
        use_extended = self.use_extended_msg_format
        if use_extended is None:
            use_extended = conf.contribs['AUTOSAR'].get('CanTSynUseExtendedMsgFormat', False)

        # Only pad 8-byte messages (Extended messages are already 16 bytes)
        if use_extended and self.type in [MESSAGE_TYPE_SYNC, MESSAGE_TYPE_FUP,
                                          MESSAGE_TYPE_SYNC_CRC, MESSAGE_TYPE_FUP_CRC,
                                          MESSAGE_TYPE_OFS, MESSAGE_TYPE_OFNS,
                                          MESSAGE_TYPE_OFS_CRC, MESSAGE_TYPE_OFNS_CRC]:
            current_len = len(pkt) + len(pay)
            if current_len < 16:
                pad = b'\x00' * (16 - current_len)
                return pkt + pay + pad

        return pkt + pay

    # CAN-specific property accessor

    @property
    def ovs(self):
        """
        Access OVS (Overflow Seconds) field from FUP messages.

        Returns:
            int: Overflow seconds (0-3), or None if not available
        """
        try:
            return self.getfieldval('ovs')
        except AttributeError:
            return None

    # Helper methods for message type identification

    def get_message_type_name(self):
        """
        Get human-readable message type name.

        Returns:
            str: Message type name (e.g., "SYNC", "FUP_CRC", "OFS_Extended")
        """
        type_names = {
            MESSAGE_TYPE_SYNC: "SYNC",
            MESSAGE_TYPE_FUP: "FUP",
            MESSAGE_TYPE_SYNC_CRC: "SYNC_CRC",
            MESSAGE_TYPE_FUP_CRC: "FUP_CRC",
            MESSAGE_TYPE_OFS: "OFS",
            MESSAGE_TYPE_OFNS: "OFNS",
            MESSAGE_TYPE_OFS_CRC: "OFS_CRC",
            MESSAGE_TYPE_OFNS_CRC: "OFNS_CRC",
            MESSAGE_TYPE_OFS_EXTENDED: "OFS_Extended",
            MESSAGE_TYPE_OFS_EXTENDED_CRC: "OFS_Extended_CRC",
        }
        return type_names.get(self.type, f"Unknown(0x{self.type:02X})")

    def is_crc_secured(self):
        """
        Check if this message type uses CRC security.

        Returns:
            bool: True if message is CRC-secured
        """
        return self.type in [MESSAGE_TYPE_SYNC_CRC, MESSAGE_TYPE_FUP_CRC,
                             MESSAGE_TYPE_OFS_CRC, MESSAGE_TYPE_OFNS_CRC,
                             MESSAGE_TYPE_OFS_EXTENDED_CRC]

    # is_sync_message() provided by TSynPropertyAccessorsMixin

    def is_followup_message(self):
        """Check if this is a Follow-Up message."""
        return self.type in [MESSAGE_TYPE_FUP, MESSAGE_TYPE_FUP_CRC]

    def is_offset_message(self):
        """Check if this is an Offset message."""
        return self.type in [MESSAGE_TYPE_OFS, MESSAGE_TYPE_OFS_CRC,
                             MESSAGE_TYPE_OFS_EXTENDED, MESSAGE_TYPE_OFS_EXTENDED_CRC]

    def is_offset_ns_message(self):
        """Check if this is an Offset Nanoseconds message."""
        return self.type in [MESSAGE_TYPE_OFNS, MESSAGE_TYPE_OFNS_CRC]

    def set_extended_msg_format(self, enabled):
        """
        Enable or disable CanTSynUseExtendedMsgFormat for this packet.

        When enabled, 8-byte messages are padded to 16 bytes for CAN FD transmission.
        This matches the AUTOSAR CanTSynUseExtendedMsgFormat parameter.

        Note: This must be called before the packet is built with bytes(). For runtime
        control of packet length, use the global configuration instead:
            conf.contribs['AUTOSAR']['CanTSynUseExtendedMsgFormat'] = True/False

        Args:
            enabled (bool): True to use 16-byte frames, False for 8-byte optimal

        Returns:
            self: For method chaining

        Example:
            >>> msg = TSynCanBase(type=0x10) / Sync(time_domain=1, seq_counter=5)
            >>> msg.use_extended_msg_format = True  # Set before bytes()
            >>> len(bytes(msg))
            16
        """
        self.use_extended_msg_format = enabled
        return self


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
