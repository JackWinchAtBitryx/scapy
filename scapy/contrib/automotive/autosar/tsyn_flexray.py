# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Jack Winch <jack.winch@bitryx.io>

# scapy.contrib.description = AUTOSAR Time Synchronization over FlexRay
# scapy.contrib.status = loads

"""
AUTOSAR Time Synchronization over FlexRay

This module implements time synchronization message formats for FlexRay.
Messages are multiplexed on the same FlexRay identifier using the Type field.

General Rules:
- Byte order: Big Endian for time value signals
- Message length: 16 bytes (all message types)
- Type field at Byte 0 acts as multiplexer

Message Types (no CRC, CRC secured):
- SYNC (0x10, 0x20): Synchronization message with seconds and nanoseconds
- OFS (0x34, 0x44): Offset message with seconds and nanoseconds

Key Differences from CAN:
- FlexRay SYNC messages combine seconds AND nanoseconds in a single message
  (CAN uses separate SYNC and FUP messages)
- All messages are exactly 16 bytes (no variable length)
- 48-bit seconds field (6 bytes) instead of 32-bit (4 bytes)
- FlexRay Cycle Counter (FCNT) field in SYNC messages
- No FUP, OFNS, or OFS Extended message types

Usage:
    from scapy.contrib.automotive.autosar.tsyn_flexray import TSynFlexRayBase

    # Build a SYNC message
    sync_msg = TSynFlexRayBase(type=0x10) / Sync(
        time_domain=1,
        seq_counter=5,
        fcnt=10,
        sgw=0,
        sync_time_sec=1234567890,
        sync_time_nsec=500000000
    )

    # Parse FlexRay frame with Tsyn message
    tsyn_msg = TSynFlexRayBase(flexray_bytes)

    # Access common fields without haslayer() checks using properties
    domain = tsyn_msg.time_domain  # Works for all message types
    counter = tsyn_msg.seq_counter  # Works for all message types
    crc_val = tsyn_msg.crc  # Returns None if not CRC-secured
    cycle = tsyn_msg.fcnt  # Returns None for OFS messages

    # Check message type using helper methods
    if tsyn_msg.is_sync_message():
        seconds = tsyn_msg.payload.sync_time_sec
        nanoseconds = tsyn_msg.payload.sync_time_nsec
        fcnt = tsyn_msg.payload.fcnt
        print(f"SYNC message: domain={domain}, time={seconds}s {nanoseconds}ns, cycle={fcnt}")
    elif tsyn_msg.is_offset_message():
        ofs_sec = tsyn_msg.payload.ofs_time_sec
        ofs_nsec = tsyn_msg.payload.ofs_time_nsec
        print(f"OFS message: domain={domain}, offset={ofs_sec}s {ofs_nsec}ns")

    # Alternative: Access type-specific fields explicitly
    if tsyn_msg.type == 0x10:
        sync_time = tsyn_msg.payload.sync_time_sec
        sync_time_ns = tsyn_msg.payload.sync_time_nsec
    elif tsyn_msg.type == 0x34:
        ofs_time = tsyn_msg.payload.ofs_time_sec
        ofs_time_ns = tsyn_msg.payload.ofs_time_nsec

    # Get human-readable message type name
    msg_type = tsyn_msg.get_message_type_name()  # Returns "SYNC", "OFS_CRC", etc.

FlexRay-Specific Fields:
    - FCNT (FlexRay Cycle Counter): 6-bit field in SYNC messages indicating the
      FlexRay communication cycle in which the message was sent
    - 48-bit seconds field: Allows representing timestamps up to ~8900 years
    - Combined timestamps: Both seconds and nanoseconds in single message for
      atomic time representation
"""

from scapy.fields import (
    BitField,
    ByteField,
    IntField,
    XByteField,
)
from scapy.packet import Packet

# Message Type Constants
MESSAGE_TYPE_SYNC = 0x10
MESSAGE_TYPE_SYNC_CRC = 0x20
MESSAGE_TYPE_OFS = 0x34
MESSAGE_TYPE_OFS_CRC = 0x44

# TODO: Review how CRC is calculated and validated for CRC secured messages.
# This implementation does not currently perform CRC checks.
# Refer to AUTOSAR specifications for CRC algorithm details.
# Implement CRC calculation and validation as needed. Keep functionality as
# minimal as possible to avoid overcomplicating the module. But should be
# able to validate and generate correct CRC values for secured messages.

# TODO: Formalise enumeration values for SGW nibble? SyncToGtm=0, SyncToSubDomain=1


class TSynFlexRayBase(Packet):
    """
    AUTOSAR Time Synchronization over FlexRay base layer

    This packet uses the Type field to determine the actual message format.
    It will automatically dispatch to the appropriate message class.

    Common fields can be accessed via properties without haslayer() checks:
    - time_domain: Available on all message types
    - seq_counter: Available on all message types
    - crc: Only on CRC-secured messages
    - user_byte_0/1/2: Varies by message type
    - sgw: Available on all message types
    - fcnt: Only on SYNC messages (FlexRay Cycle Counter)
    """
    name = "AUTOSAR Tsyn FlexRay"

    fields_desc = [
        ByteField("type", MESSAGE_TYPE_SYNC),
    ]

    def guess_payload_class(self, payload):
        """Dispatch to specific message type based on Type field"""
        type_map = {
            MESSAGE_TYPE_SYNC: Sync,
            MESSAGE_TYPE_SYNC_CRC: SyncWithCrc,
            MESSAGE_TYPE_OFS: Offset,
            MESSAGE_TYPE_OFS_CRC: OffsetWithCrc,
        }
        return type_map.get(self.type, Packet.guess_payload_class(self, payload))

    # Property accessors for common fields across message types

    @property
    def time_domain(self):
        """
        Access time_domain field from any message type.

        Returns:
            int: Time domain ID (0-15), or None if not available

        Note: For offset messages, the stored value (0-15) represents
              domain IDs 16-31 in the AUTOSAR specification.
        """
        try:
            return self.getfieldval('time_domain')
        except AttributeError:
            return None

    @property
    def seq_counter(self):
        """
        Access sequence counter field from any message type.

        Returns:
            int: Sequence counter (0-15), or None if not available
        """
        try:
            return self.getfieldval('seq_counter')
        except AttributeError:
            return None

    @property
    def crc(self):
        """
        Access CRC field from CRC-secured message types.

        Returns:
            int: CRC value, or None if message is not CRC-secured
        """
        try:
            return self.getfieldval('crc')
        except AttributeError:
            return None

    @property
    def user_byte_0(self):
        """Access user_byte_0 field if present in message type."""
        try:
            return self.getfieldval('user_byte_0')
        except AttributeError:
            return None

    @property
    def user_byte_1(self):
        """Access user_byte_1 field if present in message type."""
        try:
            return self.getfieldval('user_byte_1')
        except AttributeError:
            return None

    @property
    def user_byte_2(self):
        """Access user_byte_2 field if present in message type."""
        try:
            return self.getfieldval('user_byte_2')
        except AttributeError:
            return None

    @property
    def sgw(self):
        """
        Access SGW (Sync to Gateway/Subdomain) bit field.

        Returns:
            int: SGW value (0 or 1), or None if not available
        """
        try:
            return self.getfieldval('sgw')
        except AttributeError:
            return None

    @property
    def fcnt(self):
        """
        Access FCNT (FlexRay Cycle Counter) field from SYNC messages.

        Returns:
            int: FlexRay cycle counter (0-63), or None if not available
        """
        try:
            return self.getfieldval('fcnt')
        except AttributeError:
            return None

    # Helper methods for message type identification

    def get_message_type_name(self):
        """
        Get human-readable message type name.

        Returns:
            str: Message type name (e.g., "SYNC", "OFS_CRC")
        """
        type_names = {
            MESSAGE_TYPE_SYNC: "SYNC",
            MESSAGE_TYPE_SYNC_CRC: "SYNC_CRC",
            MESSAGE_TYPE_OFS: "OFS",
            MESSAGE_TYPE_OFS_CRC: "OFS_CRC",
        }
        return type_names.get(self.type, f"Unknown(0x{self.type:02X})")

    def is_crc_secured(self):
        """
        Check if this message type uses CRC security.

        Returns:
            bool: True if message is CRC-secured
        """
        return self.type in [MESSAGE_TYPE_SYNC_CRC, MESSAGE_TYPE_OFS_CRC]

    def is_sync_message(self):
        """Check if this is a SYNC message."""
        return self.type in [MESSAGE_TYPE_SYNC, MESSAGE_TYPE_SYNC_CRC]

    def is_offset_message(self):
        """Check if this is an Offset message."""
        return self.type in [MESSAGE_TYPE_OFS, MESSAGE_TYPE_OFS_CRC]


class Sync(Packet):
    """
    SYNC Message - Not CRC Secured (Type 0x10)

    Contains both seconds and nanoseconds for atomic time representation.
    """
    name = "AUTOSAR Tsyn FlexRay SYNC"

    fields_desc = [
        XByteField("user_byte_2", 0),
        BitField("time_domain", 0, 4),
        BitField("seq_counter", 0, 4),
        BitField("fcnt", 0, 6),
        BitField("sgw", 0, 1),
        BitField("reserved", 0, 1),
        XByteField("user_byte_0", 0),
        XByteField("user_byte_1", 0),
        BitField("sync_time_sec", 0, 48),
        IntField("sync_time_nsec", 0),
    ]


class SyncWithCrc(Packet):
    """
    SYNC Message - CRC Secured (Type 0x20)

    Contains both seconds and nanoseconds for atomic time representation.
    """
    name = "AUTOSAR Tsyn FlexRay SYNC CRC"

    fields_desc = [
        XByteField("crc", 0),
        BitField("time_domain", 0, 4),
        BitField("seq_counter", 0, 4),
        BitField("fcnt", 0, 6),
        BitField("sgw", 0, 1),
        BitField("reserved", 0, 1),
        XByteField("user_byte_0", 0),
        XByteField("user_byte_1", 0),
        BitField("sync_time_sec", 0, 48),
        IntField("sync_time_nsec", 0),
    ]


class Offset(Packet):
    """
    OFS (Offset) Message - Not CRC Secured (Type 0x34)

    Contains both seconds and nanoseconds offset values.
    """
    name = "AUTOSAR Tsyn FlexRay OFS"

    fields_desc = [
        XByteField("user_byte_2", 0),
        BitField("time_domain", 0, 4),
        BitField("seq_counter", 0, 4),
        BitField("reserved1", 0, 6),
        BitField("sgw", 0, 1),
        BitField("reserved2", 0, 1),
        XByteField("user_byte_0", 0),
        XByteField("user_byte_1", 0),
        ByteField("reserved3", 0),
        ByteField("reserved4", 0),
        IntField("ofs_time_sec", 0),
        IntField("ofs_time_nsec", 0),
    ]


class OffsetWithCrc(Packet):
    """
    OFS (Offset) Message - CRC Secured (Type 0x44)

    Contains both seconds and nanoseconds offset values.
    """
    name = "AUTOSAR Tsyn FlexRay OFS CRC"

    fields_desc = [
        XByteField("crc", 0),
        BitField("time_domain", 0, 4),
        BitField("seq_counter", 0, 4),
        BitField("reserved1", 0, 6),
        BitField("sgw", 0, 1),
        BitField("reserved2", 0, 1),
        XByteField("user_byte_0", 0),
        XByteField("user_byte_1", 0),
        ByteField("reserved3", 0),
        ByteField("reserved4", 0),
        IntField("ofs_time_sec", 0),
        IntField("ofs_time_nsec", 0),
    ]
