#!/usr/bin/env python3
"""Generate sco-fields fixtures and manifest.json from typeck path inventory."""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).parent
SCO_DIR = ROOT / "sco"
TS = "2020-01-01T00:00:00.000Z"


def sid(sco_type: str, n: int) -> str:
    return f"{sco_type}--00000000-0000-0000-0000-{n:012x}"


# Cross-reference ids
IDS = {
    "artifact": sid("artifact", 0x01),
    "autonomous_system": sid("autonomous-system", 0x02),
    "directory": sid("directory", 0x03),
    "domain_name": sid("domain-name", 0x04),
    "email_addr_from": sid("email-addr", 0x05),
    "email_addr_to": sid("email-addr", 0x06),
    "email_addr_cc": sid("email-addr", 0x20),
    "email_addr_bcc": sid("email-addr", 0x21),
    "email_addr_sender": sid("email-addr", 0x22),
    "email_message": sid("email-message", 0x07),
    "file": sid("file", 0x08),
    "file_contained": sid("file", 0x15),
    "file_image": sid("file", 0x16),
    "ipv4_addr": sid("ipv4-addr", 0x09),
    "ipv6_addr": sid("ipv6-addr", 0x0A),
    "mac_addr": sid("mac-addr", 0x0B),
    "mutex": sid("mutex", 0x0C),
    "network_traffic": sid("network-traffic", 0x0D),
    "network_traffic_encap": sid("network-traffic", 0x19),
    "process": sid("process", 0x0E),
    "process_parent": sid("process", 0x17),
    "process_child": sid("process", 0x18),
    "software": sid("software", 0x0F),
    "url": sid("url", 0x10),
    "user_account": sid("user-account", 0x11),
    "windows_registry_key": sid("windows-registry-key", 0x12),
    "x509_certificate": sid("x509-certificate", 0x13),
    "x_usb_device": sid("x-usb-device", 0x14),
    "artifact_payload_src": sid("artifact", 0x1A),
    "artifact_payload_dst": sid("artifact", 0x1B),
    "artifact_email_raw": sid("artifact", 0x1C),
}

HASH256 = "aec070645fe53ee3b3763059376134f058cc337247c978add178b6ccdfb0019f"
HASH_MD5 = "79054025255fb1a26e4bc422aef54eb4"

SCOS: dict[str, dict] = {
    "artifact": {
        "type": "artifact",
        "spec_version": "2.1",
        "id": IDS["artifact"],
        "defanged": False,
        "mime_type": "application/octet-stream",
        "payload_bin": "SGVsbG8=",
        "encryption_algorithm": "AES-256-GCM",
        "decryption_key": "secret-key",
        "hashes": {"SHA-256": HASH256, "MD5": HASH_MD5},
    },
    "autonomous-system": {
        "type": "autonomous-system",
        "spec_version": "2.1",
        "id": IDS["autonomous_system"],
        "defanged": False,
        "number": 15139,
        "name": "Slime Industries",
        "rir": "ARIN",
    },
    "directory": {
        "type": "directory",
        "spec_version": "2.1",
        "id": IDS["directory"],
        "defanged": False,
        "path": "/usr/home/temp",
        "path_enc": "L3Vzci9ob21lL3RlbXAvZW5j",
        "ctime": TS,
        "mtime": TS,
        "atime": TS,
        "contains_refs": [IDS["file_contained"], IDS["directory"]],
    },
    "domain-name": {
        "type": "domain-name",
        "spec_version": "2.1",
        "id": IDS["domain_name"],
        "defanged": False,
        "value": "example.com",
        "resolves_to_refs": [IDS["ipv4_addr"], IDS["ipv6_addr"], IDS["domain_name"]],
    },
    "email-addr": {
        "type": "email-addr",
        "spec_version": "2.1",
        "id": IDS["email_addr_from"],
        "defanged": False,
        "value": "sender@example.com",
        "display_name": "Sender Example",
        "belongs_to_ref": IDS["user_account"],
    },
    "email-addr-to": {
        "type": "email-addr",
        "spec_version": "2.1",
        "id": IDS["email_addr_to"],
        "value": "recipient@example.com",
    },
    "email-addr-cc": {
        "type": "email-addr",
        "spec_version": "2.1",
        "id": IDS["email_addr_cc"],
        "value": "cc@example.com",
    },
    "email-addr-bcc": {
        "type": "email-addr",
        "spec_version": "2.1",
        "id": IDS["email_addr_bcc"],
        "value": "bcc@example.com",
    },
    "email-addr-sender": {
        "type": "email-addr",
        "spec_version": "2.1",
        "id": IDS["email_addr_sender"],
        "value": "smtp@example.com",
    },
    "email-message": {
        "type": "email-message",
        "spec_version": "2.1",
        "id": IDS["email_message"],
        "defanged": False,
        "is_multipart": True,
        "date": TS,
        "content_type": "multipart/mixed",
        "message_id": "<msg-001@example.com>",
        "subject": "Test subject",
        "subject_enc": "encrypted-subject",
        "from_ref": IDS["email_addr_from"],
        "sender_ref": IDS["email_addr_sender"],
        "to_refs": [IDS["email_addr_to"]],
        "cc_refs": [IDS["email_addr_cc"]],
        "bcc_refs": [IDS["email_addr_bcc"]],
        "received_lines": ["from mail.example.com by mx.example.com"],
        "additional_header_fields": {"X-Custom": ["custom-value"]},
        "raw_email_ref": IDS["artifact_email_raw"],
        "body_multipart": [
            {
                "content_type": "text/plain; charset=utf-8",
                "content_disposition": "inline",
                "body": "Hello multipart",
            },
            {
                "content_type": "application/octet-stream",
                "body_raw_ref": IDS["artifact_email_raw"],
            },
        ],
    },
    "file": {
        "type": "file",
        "spec_version": "2.1",
        "id": IDS["file"],
        "defanged": False,
        "name": "sample.exe",
        "name_enc": "c2FtcGxlLmVuYw==",
        "size": 4096,
        "mime_type": "application/x-dosexec",
        "magic_number_hex": "4d5a",
        "ctime": TS,
        "mtime": TS,
        "atime": TS,
        "hashes": {"SHA-256": HASH256, "MD5": HASH_MD5},
        "parent_directory_ref": IDS["directory"],
        "contains_refs": [IDS["file_contained"]],
        "content_ref": IDS["artifact"],
        "extensions": {
            "windows-pebinary-ext": {
                "pe_type": "exe",
                "imphash": "imphash-value",
                "machine_hex": "014c",
                "number_of_sections": 3,
                "number_of_symbols": 0,
                "size_of_optional_header": 224,
                "time_date_stamp": TS,
                "pointer_to_symbol_table_hex": "00000000",
                "characteristics_hex": "0102",
                "checksum_hex": "00000000",
                "subsystem_hex": "0002",
                "dll_characteristics_hex": "0000",
                "loader_flags_hex": "00000000",
                "file_header_hashes": {"SHA-256": HASH256},
                "sections": [{"name": ".text", "size": 512, "entropy": 6.5}],
            },
            "raster-image-ext": {
                "image_height": 100,
                "image_width": 200,
                "bits_per_pixel": 24,
                "exif_tags": {"Make": "Example"},
            },
            "archive-ext": {
                "contains_refs": [IDS["file_contained"]],
                "comment": "archive comment",
            },
            "ntfs-ext": {"sid": "S-1-5-21-1234567890"},
            "pdf-ext": {
                "version": "1.7",
                "document_info_dict": {"Title": "Example"},
                "pdfid0": "pdfid0",
                "pdfid1": "pdfid1",
            },
        },
    },
    "file-contained": {
        "type": "file",
        "spec_version": "2.1",
        "id": IDS["file_contained"],
        "name": "inner.txt",
        "hashes": {"SHA-256": HASH256},
    },
    "file-image": {
        "type": "file",
        "spec_version": "2.1",
        "id": IDS["file_image"],
        "name": "proc.exe",
        "hashes": {"MD5": HASH_MD5},
    },
    "ipv4-addr": {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": IDS["ipv4_addr"],
        "defanged": False,
        "value": "198.51.100.1/32",
        "resolves_to_refs": [IDS["mac_addr"]],
        "belongs_to_refs": [IDS["autonomous_system"]],
    },
    "ipv6-addr": {
        "type": "ipv6-addr",
        "spec_version": "2.1",
        "id": IDS["ipv6_addr"],
        "defanged": False,
        "value": "2001:0db8:85a3::8a2e:0370:7334/128",
        "resolves_to_refs": [IDS["mac_addr"]],
        "belongs_to_refs": [IDS["autonomous_system"]],
    },
    "mac-addr": {
        "type": "mac-addr",
        "spec_version": "2.1",
        "id": IDS["mac_addr"],
        "defanged": False,
        "value": "08:00:27:1a:2b:3c",
    },
    "mutex": {
        "type": "mutex",
        "spec_version": "2.1",
        "id": IDS["mutex"],
        "defanged": False,
        "name": "MyMutex",
    },
    "network-traffic": {
        "type": "network-traffic",
        "spec_version": "2.1",
        "id": IDS["network_traffic"],
        "defanged": False,
        "start": TS,
        "end": TS,
        "is_active": False,
        "src_ref": IDS["ipv4_addr"],
        "dst_ref": IDS["domain_name"],
        "src_port": 443,
        "dst_port": 8443,
        "protocols": ["ipv4", "tcp"],
        "src_byte_count": 1000,
        "dst_byte_count": 2000,
        "src_packets": 10,
        "dst_packets": 20,
        "ipfix": {"flowLabel": "0x000000"},
        "src_payload_ref": IDS["artifact_payload_src"],
        "dst_payload_ref": IDS["artifact_payload_dst"],
        "encapsulates_refs": [IDS["network_traffic_encap"]],
        "encapsulated_by_ref": IDS["network_traffic_encap"],
        "extensions": {
            "http-request-ext": {
                "request_method": "get",
                "request_value": "/download.html",
                "request_version": "http/1.1",
            },
            "tcp-ext": {"src_flags_hex": "00000002"},
            "socket-ext": {
                "is_listening": True,
                "address_family": "AF_INET",
                "socket_type": "SOCK_STREAM",
            },
            "icmp-ext": {"icmp_type_hex": "08", "icmp_code_hex": "00"},
        },
    },
    "network-traffic-encap": {
        "type": "network-traffic",
        "spec_version": "2.1",
        "id": IDS["network_traffic_encap"],
        "protocols": ["ipv4"],
        "src_ref": IDS["ipv4_addr"],
    },
    "process": {
        "type": "process",
        "spec_version": "2.1",
        "id": IDS["process"],
        "defanged": False,
        "is_hidden": False,
        "pid": 4242,
        "created_time": TS,
        "cwd": "/tmp",
        "command_line": "proc.exe --verbose",
        "environment_variables": {"PATH": "/usr/bin"},
        "opened_connection_refs": [IDS["network_traffic"]],
        "creator_user_ref": IDS["user_account"],
        "image_ref": IDS["file_image"],
        "parent_ref": IDS["process_parent"],
        "child_refs": [IDS["process_child"]],
        "extensions": {
            "windows-process-ext": {
                "aslr_enabled": True,
                "dep_enabled": True,
                "priority": "HIGH_PRIORITY_CLASS",
            },
            "windows-service-ext": {
                "service_name": "sirvizio",
                "display_name": "Sirvizio",
                "start_type": "SERVICE_AUTO_START",
            },
        },
    },
    "process-parent": {
        "type": "process",
        "spec_version": "2.1",
        "id": IDS["process_parent"],
        "pid": 1,
        "command_line": "init",
    },
    "process-child": {
        "type": "process",
        "spec_version": "2.1",
        "id": IDS["process_child"],
        "pid": 4243,
        "command_line": "child.exe",
    },
    "software": {
        "type": "software",
        "spec_version": "2.1",
        "id": IDS["software"],
        "defanged": False,
        "name": "ExampleSoft",
        "cpe": "cpe:2.3:a:example:soft:1.0:*:*:*:*:*:*:*",
        "swid": "SWID-12345",
        "vendor": "Example Corp",
        "version": "1.0.0",
        "languages": ["en", "fr"],
    },
    "url": {
        "type": "url",
        "spec_version": "2.1",
        "id": IDS["url"],
        "defanged": False,
        "value": "https://example.com/path",
    },
    "user-account": {
        "type": "user-account",
        "spec_version": "2.1",
        "id": IDS["user_account"],
        "defanged": False,
        "user_id": "jdoe",
        "credential": "hashed-credential",
        "account_login": "jdoe",
        "account_type": "unix",
        "display_name": "John Doe",
        "is_service_account": False,
        "is_privileged": True,
        "can_escalate_privs": False,
        "is_disabled": False,
        "account_created": TS,
        "account_expires": TS,
        "credential_last_changed": TS,
        "account_first_login": TS,
        "account_last_login": TS,
        "extensions": {
            "unix-account-ext": {
                "gid": 1000,
                "home_dir": "/home/jdoe",
                "shell": "/bin/bash",
                "groups": ["wheel"],
            }
        },
    },
    "windows-registry-key": {
        "type": "windows-registry-key",
        "spec_version": "2.1",
        "id": IDS["windows_registry_key"],
        "defanged": False,
        "key": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Example",
        "values": [
            {"name": "Foo", "data": "bar", "data_type": "REG_SZ"},
        ],
        "modified_time": TS,
        "creator_user_ref": IDS["user_account"],
        "number_of_subkeys": 3,
    },
    "x509-certificate": {
        "type": "x509-certificate",
        "spec_version": "2.1",
        "id": IDS["x509_certificate"],
        "defanged": False,
        "is_self_signed": False,
        "hashes": {"SHA-256": HASH256},
        "version": "3",
        "serial_number": "01:02:03",
        "signature_algorithm": "sha256WithRSAEncryption",
        "issuer": "CN=Example CA",
        "subject": "CN=Example User",
        "validity_not_before": TS,
        "validity_not_after": TS,
        "subject_public_key_algorithm": "rsaEncryption",
        "subject_public_key_modulus": "modulus-hex",
        "subject_public_key_exponent": 65537,
        "x509_v3_extensions": {
            "basic_constraints": "CA:FALSE",
            "name_constraints": "nc",
            "policy_constraints": "pc",
            "key_usage": "digitalSignature",
            "extended_key_usage": "clientAuth",
            "subject_key_identifier": "ski",
            "authority_key_identifier": "aki",
            "subject_alternative_name": "san",
            "issuer_alternative_name": "ian",
            "subject_directory_attributes": "sda",
            "crl_distribution_points": "cdp",
            "inhibit_any_policy": "iap",
            "certificate_policies": "cp",
            "policy_mappings": "pm",
            "private_key_usage_period_not_before": TS,
            "private_key_usage_period_not_after": TS,
        },
    },
    "x-usb-device": {
        "type": "x-usb-device",
        "spec_version": "2.1",
        "id": IDS["x_usb_device"],
        "defanged": False,
        "usbdrive": {"serial_number": "575833314133343231313937"},
    },
    "artifact-payload-src": {
        "type": "artifact",
        "spec_version": "2.1",
        "id": IDS["artifact_payload_src"],
        "url": "https://example.com/src.bin",
        "hashes": {"SHA-256": HASH256},
    },
    "artifact-payload-dst": {
        "type": "artifact",
        "spec_version": "2.1",
        "id": IDS["artifact_payload_dst"],
        "url": "https://example.com/dst.bin",
        "hashes": {"SHA-256": HASH256},
    },
    "artifact-email-raw": {
        "type": "artifact",
        "spec_version": "2.1",
        "id": IDS["artifact_email_raw"],
        "mime_type": "message/rfc822",
        "payload_bin": "cmF3",
    },
}

# Primary SCO file name -> object key in SCOS
PRIMARY = {
    "artifact": "artifact",
    "autonomous-system": "autonomous-system",
    "directory": "directory",
    "domain-name": "domain-name",
    "email-addr": "email-addr",
    "email-message": "email-message",
    "file": "file",
    "ipv4-addr": "ipv4-addr",
    "ipv6-addr": "ipv6-addr",
    "mac-addr": "mac-addr",
    "mutex": "mutex",
    "network-traffic": "network-traffic",
    "process": "process",
    "software": "software",
    "url": "url",
    "user-account": "user-account",
    "windows-registry-key": "windows-registry-key",
    "x509-certificate": "x509-certificate",
    "x-usb-device": "x-usb-device",
}

BUNDLE_OBJECTS = [
    SCOS["artifact"],
    SCOS["autonomous-system"],
    SCOS["directory"],
    SCOS["domain-name"],
    SCOS["email-addr"],
    SCOS["email-addr-to"],
    SCOS["email-addr-cc"],
    SCOS["email-addr-bcc"],
    SCOS["email-addr-sender"],
    SCOS["email-message"],
    SCOS["file"],
    SCOS["file-contained"],
    SCOS["file-image"],
    SCOS["ipv4-addr"],
    SCOS["ipv6-addr"],
    SCOS["mac-addr"],
    SCOS["mutex"],
    SCOS["network-traffic"],
    SCOS["network-traffic-encap"],
    SCOS["process"],
    SCOS["process-parent"],
    SCOS["process-child"],
    SCOS["software"],
    SCOS["url"],
    SCOS["user-account"],
    SCOS["windows-registry-key"],
    SCOS["x509-certificate"],
    SCOS["x-usb-device"],
    SCOS["artifact-payload-src"],
    SCOS["artifact-payload-dst"],
    SCOS["artifact-email-raw"],
]


def lit(value: str | int | bool) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if value.startswith("t'"):
        return value
    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    return f"'{escaped}'"


def case_id(sco_type: str, path: str) -> str:
    return f"{sco_type}:{path}".replace("'", "")


def manifest_entry(
    sco_type: str,
    sco_file: str,
    path: str,
    pattern: str,
) -> dict:
    return {
        "id": case_id(sco_type, path),
        "pattern": pattern,
        "sco_file": f"sco/{sco_file}.json",
        "bundle_file": "full-bundle.json",
        "expect": True,
    }


def add_common_cases(sco_type: str, sco_file: str, obj: dict, cases: list[dict]) -> None:
    cases.append(
        manifest_entry(
            sco_type,
            sco_file,
            "type",
            f"[{sco_type}:type = '{obj['type']}']",
        )
    )
    cases.append(
        manifest_entry(
            sco_type,
            sco_file,
            "id",
            f"[{sco_type}:id = '{obj['id']}']",
        )
    )
    if obj.get("spec_version"):
        cases.append(
            manifest_entry(
                sco_type,
                sco_file,
                "spec_version",
                f"[{sco_type}:spec_version = '{obj['spec_version']}']",
            )
        )
    if "defanged" in obj:
        cases.append(
            manifest_entry(
                sco_type,
                sco_file,
                "defanged",
                f"[{sco_type}:defanged = {lit(obj['defanged'])}]",
            )
        )
    if obj.get("extensions"):
        cases.append(
            manifest_entry(
                sco_type,
                sco_file,
                "extensions",
                f"[EXISTS {sco_type}:extensions]",
            )
        )


def build_manifest() -> list[dict]:
    cases: list[dict] = []

    def add(sco_type: str, sco_file: str, path: str, pattern: str) -> None:
        cases.append(manifest_entry(sco_type, sco_file, path, pattern))

    for sco_file, key in PRIMARY.items():
        obj = SCOS[key]
        add_common_cases(sco_file, sco_file, obj, cases)

    # artifact
    o = SCOS["artifact"]
    add("artifact", "artifact", "mime_type", f"[artifact:mime_type = {lit(o['mime_type'])}]")
    add("artifact", "artifact", "payload_bin", f"[EXISTS artifact:payload_bin]")
    add("artifact", "artifact", "encryption_algorithm", f"[artifact:encryption_algorithm = {lit(o['encryption_algorithm'])}]")
    add("artifact", "artifact", "decryption_key", f"[artifact:decryption_key = {lit(o['decryption_key'])}]")
    add("artifact", "artifact", "hashes", f"[EXISTS artifact:hashes]")
    add("artifact", "artifact", "hashes.SHA-256", f"[artifact:hashes.'SHA-256' = {lit(HASH256)}]")

    # autonomous-system
    o = SCOS["autonomous-system"]
    add("autonomous-system", "autonomous-system", "number", f"[autonomous-system:number = {o['number']}]")
    add("autonomous-system", "autonomous-system", "name", f"[autonomous-system:name = {lit(o['name'])}]")
    add("autonomous-system", "autonomous-system", "rir", f"[autonomous-system:rir = {lit(o['rir'])}]")

    # directory
    o = SCOS["directory"]
    add("directory", "directory", "path", f"[directory:path = {lit(o['path'])}]")
    add("directory", "directory", "path_enc", f"[directory:path_enc = {lit(o['path_enc'])}]")
    add("directory", "directory", "ctime", f"[directory:ctime = t'{TS}']")
    add("directory", "directory", "mtime", f"[directory:mtime = t'{TS}']")
    add("directory", "directory", "atime", f"[directory:atime = t'{TS}']")
    add("directory", "directory", "contains_refs", f"[EXISTS directory:contains_refs]")
    add("directory", "directory", "contains_refs[0]", f"[directory:contains_refs[0] = {lit(IDS['file_contained'])}]")

    # domain-name
    o = SCOS["domain-name"]
    add("domain-name", "domain-name", "value", f"[domain-name:value = {lit(o['value'])}]")
    add("domain-name", "domain-name", "resolves_to_refs", f"[EXISTS domain-name:resolves_to_refs]")
    add("domain-name", "domain-name", "resolves_to_refs[0]", f"[domain-name:resolves_to_refs[0] = {lit(IDS['ipv4_addr'])}]")

    # email-addr
    o = SCOS["email-addr"]
    add("email-addr", "email-addr", "value", f"[email-addr:value = {lit(o['value'])}]")
    add("email-addr", "email-addr", "display_name", f"[email-addr:display_name = {lit(o['display_name'])}]")
    add("email-addr", "email-addr", "belongs_to_ref", f"[email-addr:belongs_to_ref = {lit(IDS['user_account'])}]")

    # email-message
    o = SCOS["email-message"]
    add("email-message", "email-message", "is_multipart", f"[email-message:is_multipart = true]")
    add("email-message", "email-message", "date", f"[email-message:date = t'{TS}']")
    add("email-message", "email-message", "content_type", f"[email-message:content_type = {lit(o['content_type'])}]")
    add("email-message", "email-message", "message_id", f"[email-message:message_id = {lit(o['message_id'])}]")
    add("email-message", "email-message", "subject", f"[email-message:subject = {lit(o['subject'])}]")
    add("email-message", "email-message", "subject_enc", f"[email-message:subject_enc = {lit(o['subject_enc'])}]")
    add("email-message", "email-message", "from_ref", f"[email-message:from_ref = {lit(IDS['email_addr_from'])}]")
    add("email-message", "email-message", "sender_ref", f"[email-message:sender_ref = {lit(IDS['email_addr_sender'])}]")
    add("email-message", "email-message", "to_refs", f"[EXISTS email-message:to_refs]")
    add("email-message", "email-message", "to_refs[0]", f"[email-message:to_refs[0] = {lit(IDS['email_addr_to'])}]")
    add("email-message", "email-message", "cc_refs", f"[EXISTS email-message:cc_refs]")
    add("email-message", "email-message", "cc_refs[0]", f"[email-message:cc_refs[0] = {lit(IDS['email_addr_cc'])}]")
    add("email-message", "email-message", "bcc_refs", f"[EXISTS email-message:bcc_refs]")
    add("email-message", "email-message", "bcc_refs[0]", f"[email-message:bcc_refs[0] = {lit(IDS['email_addr_bcc'])}]")
    add("email-message", "email-message", "received_lines", f"[EXISTS email-message:received_lines]")
    add("email-message", "email-message", "additional_header_fields", f"[EXISTS email-message:additional_header_fields]")
    add("email-message", "email-message", "body_multipart", f"[EXISTS email-message:body_multipart]")
    add("email-message", "email-message", "body_multipart[0].body", f"[email-message:body_multipart[0].body = {lit('Hello multipart')}]")
    add("email-message", "email-message", "body_multipart[0].content_type", f"[email-message:body_multipart[0].content_type = {lit('text/plain; charset=utf-8')}]")
    add("email-message", "email-message", "body_multipart[0].content_disposition", f"[email-message:body_multipart[0].content_disposition = {lit('inline')}]")
    add("email-message", "email-message", "body_multipart[1].body_raw_ref", f"[email-message:body_multipart[1].body_raw_ref = {lit(IDS['artifact_email_raw'])}]")
    add("email-message", "email-message", "raw_email_ref", f"[email-message:raw_email_ref = {lit(IDS['artifact_email_raw'])}]")

    # file
    o = SCOS["file"]
    add("file", "file", "hashes", f"[EXISTS file:hashes]")
    add("file", "file", "hashes.MD5", f"[file:hashes.'MD5' = {lit(HASH_MD5)}]")
    add("file", "file", "size", f"[file:size = {o['size']}]")
    add("file", "file", "name", f"[file:name = {lit(o['name'])}]")
    add("file", "file", "name_enc", f"[file:name_enc = {lit(o['name_enc'])}]")
    add("file", "file", "magic_number_hex", f"[file:magic_number_hex = {lit(o['magic_number_hex'])}]")
    add("file", "file", "mime_type", f"[file:mime_type = {lit(o['mime_type'])}]")
    add("file", "file", "ctime", f"[file:ctime = t'{TS}']")
    add("file", "file", "mtime", f"[file:mtime = t'{TS}']")
    add("file", "file", "atime", f"[file:atime = t'{TS}']")
    add("file", "file", "parent_directory_ref", f"[file:parent_directory_ref = {lit(IDS['directory'])}]")
    add("file", "file", "contains_refs", f"[EXISTS file:contains_refs]")
    add("file", "file", "contains_refs[0]", f"[file:contains_refs[0] = {lit(IDS['file_contained'])}]")
    add("file", "file", "content_ref", f"[file:content_ref = {lit(IDS['artifact'])}]")
    pe = "extensions.'windows-pebinary-ext'"
    add("file", "file", f"{pe}.pe_type", f"[file:{pe}.pe_type = 'exe']")
    add("file", "file", f"{pe}.imphash", f"[file:{pe}.imphash = 'imphash-value']")
    add("file", "file", f"{pe}.machine_hex", f"[file:{pe}.machine_hex = '014c']")
    add("file", "file", f"{pe}.number_of_sections", f"[file:{pe}.number_of_sections = 3]")
    add("file", "file", f"{pe}.number_of_symbols", f"[file:{pe}.number_of_symbols = 0]")
    add("file", "file", f"{pe}.size_of_optional_header", f"[file:{pe}.size_of_optional_header = 224]")
    add("file", "file", f"{pe}.time_date_stamp", f"[file:{pe}.time_date_stamp = t'{TS}']")
    add("file", "file", f"{pe}.pointer_to_symbol_table_hex", f"[file:{pe}.pointer_to_symbol_table_hex = '00000000']")
    add("file", "file", f"{pe}.characteristics_hex", f"[file:{pe}.characteristics_hex = '0102']")
    add("file", "file", f"{pe}.checksum_hex", f"[file:{pe}.checksum_hex = '00000000']")
    add("file", "file", f"{pe}.subsystem_hex", f"[file:{pe}.subsystem_hex = '0002']")
    add("file", "file", f"{pe}.dll_characteristics_hex", f"[file:{pe}.dll_characteristics_hex = '0000']")
    add("file", "file", f"{pe}.loader_flags_hex", f"[file:{pe}.loader_flags_hex = '00000000']")
    add("file", "file", f"{pe}.file_header_hashes", f"[EXISTS file:{pe}.file_header_hashes]")
    add("file", "file", f"{pe}.sections", f"[EXISTS file:{pe}.sections]")
    add("file", "file", f"{pe}.sections[0].name", f"[file:{pe}.sections[0].name = '.text']")
    add("file", "file", f"{pe}.sections[0].size", f"[file:{pe}.sections[0].size = 512]")
    add("file", "file", f"{pe}.sections[0].entropy", f"[file:{pe}.sections[0].entropy = 6.5]")
    ri = "extensions.'raster-image-ext'"
    add("file", "file", f"{ri}.image_height", f"[file:{ri}.image_height = '100']")
    add("file", "file", f"{ri}.image_width", f"[file:{ri}.image_width = '200']")
    add("file", "file", f"{ri}.bits_per_pixel", f"[file:{ri}.bits_per_pixel = '24']")
    add("file", "file", f"{ri}.exif_tags", f"[EXISTS file:{ri}.exif_tags]")
    ae = "extensions.'archive-ext'"
    add("file", "file", f"{ae}.contains_refs", f"[EXISTS file:{ae}.contains_refs]")
    add("file", "file", f"{ae}.comment", f"[file:{ae}.comment = 'archive comment']")
    add("file", "file", "extensions.'ntfs-ext'.sid", f"[file:extensions.'ntfs-ext'.sid = 'S-1-5-21-1234567890']")
    pdf = "extensions.'pdf-ext'"
    add("file", "file", f"{pdf}.version", f"[file:{pdf}.version = '1.7']")
    add("file", "file", f"{pdf}.document_info_dict", f"[EXISTS file:{pdf}.document_info_dict]")
    add("file", "file", f"{pdf}.pdfid0", f"[file:{pdf}.pdfid0 = 'pdfid0']")
    add("file", "file", f"{pdf}.pdfid1", f"[file:{pdf}.pdfid1 = 'pdfid1']")

    # ipv4-addr
    o = SCOS["ipv4-addr"]
    add("ipv4-addr", "ipv4-addr", "value", f"[ipv4-addr:value = {lit(o['value'])}]")
    add("ipv4-addr", "ipv4-addr", "resolves_to_refs", f"[EXISTS ipv4-addr:resolves_to_refs]")
    add("ipv4-addr", "ipv4-addr", "resolves_to_refs[0]", f"[ipv4-addr:resolves_to_refs[0] = {lit(IDS['mac_addr'])}]")
    add("ipv4-addr", "ipv4-addr", "belongs_to_refs", f"[EXISTS ipv4-addr:belongs_to_refs]")
    add("ipv4-addr", "ipv4-addr", "belongs_to_refs[0]", f"[ipv4-addr:belongs_to_refs[0] = {lit(IDS['autonomous_system'])}]")

    # ipv6-addr
    o = SCOS["ipv6-addr"]
    add("ipv6-addr", "ipv6-addr", "value", f"[ipv6-addr:value = {lit(o['value'])}]")
    add("ipv6-addr", "ipv6-addr", "resolves_to_refs", f"[EXISTS ipv6-addr:resolves_to_refs]")
    add("ipv6-addr", "ipv6-addr", "belongs_to_refs", f"[EXISTS ipv6-addr:belongs_to_refs]")

    # mac-addr
    o = SCOS["mac-addr"]
    add("mac-addr", "mac-addr", "value", f"[mac-addr:value = {lit(o['value'])}]")

    # mutex
    o = SCOS["mutex"]
    add("mutex", "mutex", "name", f"[mutex:name = {lit(o['name'])}]")

    # network-traffic
    o = SCOS["network-traffic"]
    add("network-traffic", "network-traffic", "start", f"[network-traffic:start = t'{TS}']")
    add("network-traffic", "network-traffic", "end", f"[network-traffic:end = t'{TS}']")
    add("network-traffic", "network-traffic", "is_active", f"[network-traffic:is_active = false]")
    add("network-traffic", "network-traffic", "src_ref", f"[network-traffic:src_ref = {lit(IDS['ipv4_addr'])}]")
    add("network-traffic", "network-traffic", "dst_ref", f"[network-traffic:dst_ref = {lit(IDS['domain_name'])}]")
    add("network-traffic", "network-traffic", "src_port", f"[network-traffic:src_port = 443]")
    add("network-traffic", "network-traffic", "dst_port", f"[network-traffic:dst_port = 8443]")
    add("network-traffic", "network-traffic", "protocols", f"[EXISTS network-traffic:protocols]")
    add("network-traffic", "network-traffic", "src_byte_count", f"[network-traffic:src_byte_count = 1000]")
    add("network-traffic", "network-traffic", "dst_byte_count", f"[network-traffic:dst_byte_count = 2000]")
    add("network-traffic", "network-traffic", "src_packets", f"[network-traffic:src_packets = 10]")
    add("network-traffic", "network-traffic", "dst_packets", f"[network-traffic:dst_packets = 20]")
    add("network-traffic", "network-traffic", "ipfix", f"[EXISTS network-traffic:ipfix]")
    add("network-traffic", "network-traffic", "src_payload_ref", f"[network-traffic:src_payload_ref = {lit(IDS['artifact_payload_src'])}]")
    add("network-traffic", "network-traffic", "dst_payload_ref", f"[network-traffic:dst_payload_ref = {lit(IDS['artifact_payload_dst'])}]")
    add("network-traffic", "network-traffic", "encapsulates_refs", f"[EXISTS network-traffic:encapsulates_refs]")
    add("network-traffic", "network-traffic", "encapsulated_by_ref", f"[network-traffic:encapsulated_by_ref = {lit(IDS['network_traffic_encap'])}]")
    add("network-traffic", "network-traffic", "extensions.'http-request-ext'.request_method", f"[network-traffic:extensions.'http-request-ext'.request_method = 'get']")
    add("network-traffic", "network-traffic", "extensions.'tcp-ext'.src_flags_hex", f"[network-traffic:extensions.'tcp-ext'.src_flags_hex = '00000002']")
    add("network-traffic", "network-traffic", "extensions.'socket-ext'.is_listening", f"[network-traffic:extensions.'socket-ext'.is_listening = 'true']")
    add("network-traffic", "network-traffic", "extensions.'icmp-ext'.icmp_type_hex", f"[network-traffic:extensions.'icmp-ext'.icmp_type_hex = '08']")

    # process
    o = SCOS["process"]
    add("process", "process", "name", f"[process:name = 'proc.exe']")
    add("process", "process", "cwd", f"[process:cwd = {lit(o['cwd'])}]")
    add("process", "process", "command_line", f"[process:command_line = {lit(o['command_line'])}]")
    add("process", "process", "is_hidden", f"[process:is_hidden = false]")
    add("process", "process", "pid", f"[process:pid = 4242]")
    add("process", "process", "created_time", f"[process:created_time = t'{TS}']")
    add("process", "process", "environment_variables", f"[EXISTS process:environment_variables]")
    add("process", "process", "opened_connection_refs", f"[EXISTS process:opened_connection_refs]")
    add("process", "process", "creator_user_ref", f"[process:creator_user_ref = {lit(IDS['user_account'])}]")
    add("process", "process", "image_ref", f"[process:image_ref = {lit(IDS['file_image'])}]")
    add("process", "process", "parent_ref", f"[process:parent_ref = {lit(IDS['process_parent'])}]")
    add("process", "process", "child_refs", f"[EXISTS process:child_refs]")
    add("process", "process", "child_refs[0]", f"[process:child_refs[0] = {lit(IDS['process_child'])}]")
    add("process", "process", "extensions.'windows-process-ext'.aslr_enabled", f"[process:extensions.'windows-process-ext'.aslr_enabled = 'true']")
    add("process", "process", "extensions.'windows-service-ext'.service_name", f"[process:extensions.'windows-service-ext'.service_name = 'sirvizio']")

    # software
    o = SCOS["software"]
    add("software", "software", "name", f"[software:name = {lit(o['name'])}]")
    add("software", "software", "cpe", f"[software:cpe = {lit(o['cpe'])}]")
    add("software", "software", "swid", f"[software:swid = {lit(o['swid'])}]")
    add("software", "software", "vendor", f"[software:vendor = {lit(o['vendor'])}]")
    add("software", "software", "version", f"[software:version = {lit(o['version'])}]")
    add("software", "software", "languages", f"[EXISTS software:languages]")

    # url
    o = SCOS["url"]
    add("url", "url", "value", f"[url:value = {lit(o['value'])}]")

    # user-account
    o = SCOS["user-account"]
    add("user-account", "user-account", "user_id", f"[user-account:user_id = {lit(o['user_id'])}]")
    add("user-account", "user-account", "credential", f"[user-account:credential = {lit(o['credential'])}]")
    add("user-account", "user-account", "account_login", f"[user-account:account_login = {lit(o['account_login'])}]")
    add("user-account", "user-account", "account_type", f"[user-account:account_type = {lit(o['account_type'])}]")
    add("user-account", "user-account", "display_name", f"[user-account:display_name = {lit(o['display_name'])}]")
    add("user-account", "user-account", "is_service_account", f"[user-account:is_service_account = false]")
    add("user-account", "user-account", "is_privileged", f"[user-account:is_privileged = true]")
    add("user-account", "user-account", "can_escalate_privs", f"[user-account:can_escalate_privs = false]")
    add("user-account", "user-account", "is_disabled", f"[user-account:is_disabled = false]")
    add("user-account", "user-account", "account_created", f"[user-account:account_created = t'{TS}']")
    add("user-account", "user-account", "account_expires", f"[user-account:account_expires = t'{TS}']")
    add("user-account", "user-account", "credential_last_changed", f"[user-account:credential_last_changed = t'{TS}']")
    add("user-account", "user-account", "account_first_login", f"[user-account:account_first_login = t'{TS}']")
    add("user-account", "user-account", "account_last_login", f"[user-account:account_last_login = t'{TS}']")
    ua = "extensions.'unix-account-ext'"
    add("user-account", "user-account", f"{ua}.gid", f"[EXISTS user-account:{ua}.gid]")
    add("user-account", "user-account", f"{ua}.home_dir", f"[user-account:{ua}.home_dir = '/home/jdoe']")
    add("user-account", "user-account", f"{ua}.shell", f"[user-account:{ua}.shell = '/bin/bash']")
    add("user-account", "user-account", f"{ua}.groups", f"[EXISTS user-account:{ua}.groups]")

    # windows-registry-key
    o = SCOS["windows-registry-key"]
    add("windows-registry-key", "windows-registry-key", "key", f"[windows-registry-key:key = {lit(o['key'])}]")
    add("windows-registry-key", "windows-registry-key", "values", f"[EXISTS windows-registry-key:values]")
    add("windows-registry-key", "windows-registry-key", "values[0].name", f"[windows-registry-key:values[0].name = 'Foo']")
    add("windows-registry-key", "windows-registry-key", "values[0].data", f"[windows-registry-key:values[0].data = 'bar']")
    add("windows-registry-key", "windows-registry-key", "values[0].data_type", f"[windows-registry-key:values[0].data_type = 'REG_SZ']")
    add("windows-registry-key", "windows-registry-key", "modified_time", f"[windows-registry-key:modified_time = t'{TS}']")
    add("windows-registry-key", "windows-registry-key", "creator_user_ref", f"[windows-registry-key:creator_user_ref = {lit(IDS['user_account'])}]")
    add("windows-registry-key", "windows-registry-key", "number_of_subkeys", f"[windows-registry-key:number_of_subkeys = 3]")

    # x509-certificate
    o = SCOS["x509-certificate"]
    add("x509-certificate", "x509-certificate", "is_self_signed", f"[x509-certificate:is_self_signed = false]")
    add("x509-certificate", "x509-certificate", "hashes", f"[EXISTS x509-certificate:hashes]")
    add("x509-certificate", "x509-certificate", "version", f"[x509-certificate:version = '3']")
    add("x509-certificate", "x509-certificate", "serial_number", f"[x509-certificate:serial_number = '01:02:03']")
    add("x509-certificate", "x509-certificate", "signature_algorithm", f"[x509-certificate:signature_algorithm = 'sha256WithRSAEncryption']")
    add("x509-certificate", "x509-certificate", "issuer", f"[x509-certificate:issuer = 'CN=Example CA']")
    add("x509-certificate", "x509-certificate", "subject", f"[x509-certificate:subject = 'CN=Example User']")
    add("x509-certificate", "x509-certificate", "validity_not_before", f"[x509-certificate:validity_not_before = t'{TS}']")
    add("x509-certificate", "x509-certificate", "validity_not_after", f"[x509-certificate:validity_not_after = t'{TS}']")
    add("x509-certificate", "x509-certificate", "subject_public_key_algorithm", f"[x509-certificate:subject_public_key_algorithm = 'rsaEncryption']")
    add("x509-certificate", "x509-certificate", "subject_public_key_modulus", f"[x509-certificate:subject_public_key_modulus = 'modulus-hex']")
    add("x509-certificate", "x509-certificate", "subject_public_key_exponent", f"[x509-certificate:subject_public_key_exponent = 65537]")
    add("x509-certificate", "x509-certificate", "x509_v3_extensions", f"[EXISTS x509-certificate:x509_v3_extensions]")
    for ext_field in o["x509_v3_extensions"]:
        val = o["x509_v3_extensions"][ext_field]
        if ext_field.endswith("_not_before") or ext_field.endswith("_not_after"):
            add("x509-certificate", "x509-certificate", f"x509_v3_extensions.{ext_field}", f"[x509-certificate:x509_v3_extensions.{ext_field} = t'{TS}']")
        else:
            add("x509-certificate", "x509-certificate", f"x509_v3_extensions.{ext_field}", f"[x509-certificate:x509_v3_extensions.{ext_field} = {lit(val)}]")

    # x-usb-device custom
    add("x-usb-device", "x-usb-device", "usbdrive.serial_number", f"[x-usb-device:usbdrive.serial_number = '575833314133343231313937']")

    return cases


def main() -> None:
    SCO_DIR.mkdir(parents=True, exist_ok=True)
    for filename, key in PRIMARY.items():
        path = SCO_DIR / f"{filename}.json"
        path.write_text(json.dumps(SCOS[key], indent=2) + "\n", encoding="utf-8")

    bundle = {
        "type": "bundle",
        "id": "bundle--00000000-0000-0000-0000-000000000001",
        "objects": BUNDLE_OBJECTS,
    }
    (ROOT / "full-bundle.json").write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")

    manifest = build_manifest()
    (ROOT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Generated {len(manifest)} manifest cases and {len(BUNDLE_OBJECTS)} bundle objects")


if __name__ == "__main__":
    main()
