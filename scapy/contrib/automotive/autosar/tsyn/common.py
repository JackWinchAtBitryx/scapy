# SPDX-License-Identifier: GPL-2.0-only
# This file is part of Scapy
# See https://scapy.net/ for more information
# Copyright (C) Jack Winch <jack.winch@bitryx.io>

# scapy.contrib.description = AUTOSAR Time Synchronization - Common Definitions
# scapy.contrib.status = loads

"""
AUTOSAR Time Synchronization - Common Definitions

Shared constants and base functionality for CAN and FlexRay TSyn protocols.

This module provides:
- Shared message type constants (SYNC, SYNC_CRC, OFS, OFS_CRC)
- Common property accessor mixin for safe field access
- Shared TODO comments for future CRC implementation
"""

# Shared Message Type Constants
# These constants are used by both CAN and FlexRay TSyn protocols
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


class TSynPropertyAccessorsMixin:
    """
    Mixin providing common property accessors for TSyn messages.

    This mixin provides safe access to common fields across different
    message types without requiring haslayer() checks. It uses a try/except
    pattern to gracefully handle missing fields by returning None.

    Properties provided:
    - time_domain: Time domain ID (0-15)
    - seq_counter: Sequence counter (0-15)
    - crc: CRC value (only on CRC-secured messages)
    - user_byte_0/1/2: OEM-specific user data bytes
    - sgw: Sync to Gateway/Subdomain bit

    Methods provided:
    - is_sync_message(): Check if message is SYNC type

    Usage:
        class MyTSynPacket(TSynPropertyAccessorsMixin, Packet):
            # Your packet implementation
            pass

        pkt = MyTSynPacket(type=0x10) / SomePayload(time_domain=5)
        domain = pkt.time_domain  # Returns 5, no haslayer() needed
    """

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

    def is_sync_message(self):
        """
        Check if this is a SYNC message.

        Returns:
            bool: True if message type is SYNC (0x10) or SYNC_CRC (0x20)
        """
        return self.type in [MESSAGE_TYPE_SYNC, MESSAGE_TYPE_SYNC_CRC]
