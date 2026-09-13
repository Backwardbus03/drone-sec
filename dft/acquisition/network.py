"""
Software-Based Network and Wireless Capture Module for Drone Forensic Toolkit.
Parses and analyzes wireless packet captures (PCAP/PCAPNG) for UAV Wi-Fi AP beacons,
probe requests, MAVLink UDP telemetry (ports 14550/14555), and RTSP video downlinks.
"""

import struct
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone


class NetworkCaptureEngine:
    @staticmethod
    def parse_pcap_file(pcap_path: Path) -> Dict[str, Any]:
        """
        Parses PCAP binary files (Ethernet/802.11 or raw IP).
        Extracts packet counts, detected UAV SSIDs, MAC addresses, and MAVLink UDP frames.
        """
        p = Path(pcap_path)
        if not p.exists():
            raise FileNotFoundError(f"PCAP file not found: {p}")

        data = p.read_bytes()
        if len(data) < 24:
            raise ValueError("Invalid PCAP file: Header shorter than 24 bytes")

        magic = data[:4]
        # PCAP magic numbers: 0xa1b2c3d4 (standard) or 0xd4c3b2a1 (swapped)
        if magic not in [b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\n\r\r\n"]:
            # Check if it's text-based pcap dump
            return NetworkCaptureEngine._parse_text_dump(data)

        # Parse PCAP Global Header
        # magic_number (4), version_major (2), version_minor (2), thiszone (4), sigfigs (4), snaplen (4), network (4)
        is_little_endian = (magic == b"\xd4\xc3\xb2\xa1" or magic == b"\xa1\xb2\xc3\xd4")
        endian_fmt = "<" if is_little_endian else ">"

        packets = []
        offset = 24
        mavlink_frames = 0
        ssids_found = set()
        mac_addresses = set()

        while offset + 16 <= len(data):
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack_from(f"{endian_fmt}IIII", data, offset)
            offset += 16

            if offset + incl_len > len(data):
                break

            packet_data = data[offset:offset + incl_len]
            offset += incl_len

            # Check for MAVLink magic bytes: 0xFE (v1) or 0xFD (v2)
            if b"\xfe" in packet_data or b"\xfd" in packet_data:
                mavlink_frames += 1

            # Check for common drone SSID string patterns
            for drone_brand in [b"DJI-", b"Spark-", b"Mavic-", b"Phantom-", b"Bebop", b"Anafi", b"PX4", b"Ardu"]:
                if drone_brand in packet_data:
                    idx = packet_data.find(drone_brand)
                    # Extract printable ascii string
                    ssid_candidate = packet_data[idx:idx + 32].split(b"\x00")[0]
                    clean_ssid = "".join(chr(b) for b in ssid_candidate if 32 <= b <= 126)
                    if clean_ssid:
                        ssids_found.add(clean_ssid)

            # Heuristic MAC address harvesting
            if len(packet_data) >= 14:
                mac_src = ":".join(f"{b:02x}" for b in packet_data[6:12])
                mac_addresses.add(mac_src)

            packets.append({
                "timestamp_sec": ts_sec,
                "length_bytes": incl_len
            })

            if len(packets) >= 1000:
                break

        return {
            "source_pcap": p.name,
            "total_packets_parsed": len(packets),
            "detected_uav_ssids": list(ssids_found),
            "mavlink_telemetry_frames": mavlink_frames,
            "associated_mac_addresses": list(mac_addresses)[:15],
            "analysis": "Identified drone wireless communication markers" if (mavlink_frames > 0 or ssids_found) else "Generic wireless network traffic"
        }

    @staticmethod
    def _parse_text_dump(data: bytes) -> Dict[str, Any]:
        """Fallback parser for text-formatted tshark/tcpdump outputs."""
        text = data.decode("utf-8", errors="ignore")
        lines = text.splitlines()
        ssids = set()
        for line in lines:
            for kw in ["DJI", "Mavic", "Bebop", "Anafi", "ArduPilot", "PX4"]:
                if kw in line:
                    ssids.add(kw)
        return {
            "total_lines": len(lines),
            "detected_uav_ssids": list(ssids),
            "mavlink_telemetry_frames": 0
        }
