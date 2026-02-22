"""
parser.py — BloodHound SharpHound ZIP/JSON Parser

Parses SharpHound collection ZIP files and builds a unified
data model with SID-to-name mappings, group memberships, and ACE relationships.
"""

import zipfile
import json
import os
from collections import defaultdict


# Well-known SID suffixes → friendly names
WELL_KNOWN_SIDS = {
    "S-1-0-0": "Nobody",
    "S-1-1-0": "Everyone",
    "S-1-5-7": "Anonymous Logon",
    "S-1-5-11": "Authenticated Users",
    "S-1-5-18": "SYSTEM",
    "S-1-5-19": "LOCAL SERVICE",
    "S-1-5-20": "NETWORK SERVICE",
}

# Well-known RID suffixes for domain SIDs
WELL_KNOWN_RIDS = {
    "500": "Administrator",
    "501": "Guest",
    "502": "krbtgt",
    "512": "Domain Admins",
    "513": "Domain Users",
    "514": "Domain Guests",
    "515": "Domain Computers",
    "516": "Domain Controllers",
    "517": "Cert Publishers",
    "518": "Schema Admins",
    "519": "Enterprise Admins",
    "520": "Group Policy Creator Owners",
    "521": "Read-Only Domain Controllers",
    "526": "Key Admins",
    "527": "Enterprise Key Admins",
    "544": "Administrators",
    "548": "Account Operators",
    "549": "Server Operators",
    "550": "Print Operators",
    "551": "Backup Operators",
    "552": "Replicator",
}

# High-value group RIDs that are always interesting
HIGH_VALUE_RIDS = {"512", "516", "518", "519", "544", "548", "549", "550", "551"}


def detect_file_type(data: dict) -> str | None:
    """Detect the type of BloodHound JSON file from its metadata."""
    meta = data.get("meta", {})
    file_type = meta.get("type", "").lower()
    if file_type:
        return file_type
    # Fallback: guess from data structure
    if "data" in data and len(data["data"]) > 0:
        sample = data["data"][0]
        if "Members" in sample:
            return "groups"
        if "SPNTargets" in sample:
            return "users"
        if "Trusts" in sample:
            return "domains"
        if "gpcpath" in sample.get("Properties", {}):
            return "gpos"
        if "blocksinheritance" in sample.get("Properties", {}):
            return "ous"
        if "ChildObjects" in sample:
            return "containers"
        if "Sessions" in sample or "LocalAdmins" in sample:
            return "computers"
    return None


def parse_zip(zip_path: str) -> dict:
    """
    Parse a BloodHound SharpHound ZIP file and return a unified data model.

    Returns:
        dict with keys:
            - domain: domain info dict
            - users: dict[SID] = user_obj
            - groups: dict[SID] = group_obj
            - computers: dict[SID] = computer_obj
            - gpos: dict[id] = gpo_obj
            - ous: dict[id] = ou_obj
            - containers: dict[id] = container_obj
            - sid_to_name: dict[SID] = friendly_name
            - sid_to_type: dict[SID] = object_type
            - group_memberships: dict[group_SID] = [member_SIDs]
            - reverse_memberships: dict[member_SID] = [group_SIDs]
            - aces: list of all ACE relationships
            - meta: parsing metadata
    """
    if not os.path.isfile(zip_path):
        raise FileNotFoundError(f"ZIP file not found: {zip_path}")

    result = {
        "domain": None,
        "users": {},
        "groups": {},
        "computers": {},
        "gpos": {},
        "ous": {},
        "containers": {},
        "sid_to_name": {},
        "sid_to_type": {},
        "group_memberships": defaultdict(list),
        "reverse_memberships": defaultdict(list),
        "aces": [],
        "meta": {
            "zip_path": zip_path,
            "files_parsed": [],
            "total_objects": 0,
        },
    }

    with zipfile.ZipFile(zip_path, "r") as zf:
        for entry in zf.infolist():
            if entry.is_dir() or not entry.filename.endswith(".json"):
                continue

            try:
                raw = zf.read(entry.filename)
                data = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError) as e:
                result["meta"]["files_parsed"].append(
                    {"file": entry.filename, "status": "error", "error": str(e)}
                )
                continue

            file_type = detect_file_type(data)
            if not file_type:
                # Try filename-based detection
                fname_lower = entry.filename.lower()
                for t in ["users", "groups", "computers", "domains", "gpos", "ous", "containers"]:
                    if t in fname_lower:
                        file_type = t
                        break

            if not file_type:
                result["meta"]["files_parsed"].append(
                    {"file": entry.filename, "status": "skipped", "reason": "unknown type"}
                )
                continue

            objects = data.get("data", [])
            count = len(objects)
            result["meta"]["files_parsed"].append(
                {"file": entry.filename, "status": "ok", "type": file_type, "count": count}
            )
            result["meta"]["total_objects"] += count

            # Process each object type
            if file_type == "users":
                _process_users(objects, result)
            elif file_type == "groups":
                _process_groups(objects, result)
            elif file_type == "computers":
                _process_computers(objects, result)
            elif file_type == "domains":
                _process_domains(objects, result)
            elif file_type == "gpos":
                _process_gpos(objects, result)
            elif file_type == "ous":
                _process_ous(objects, result)
            elif file_type == "containers":
                _process_containers(objects, result)

    # Populate well-known SID names
    _populate_wellknown_sids(result)

    return result


def _process_users(objects: list, result: dict):
    """Process user objects."""
    for obj in objects:
        sid = obj.get("ObjectIdentifier", "")
        props = obj.get("Properties", {})
        name = props.get("name", "")

        if sid:
            result["users"][sid] = obj
            if name:
                result["sid_to_name"][sid] = name
            result["sid_to_type"][sid] = "User"

        # Collect ACEs
        for ace in obj.get("Aces", []):
            ace["TargetSID"] = sid
            ace["TargetType"] = "User"
            ace["TargetName"] = name
            result["aces"].append(ace)


def _process_groups(objects: list, result: dict):
    """Process group objects and build membership maps."""
    for obj in objects:
        sid = obj.get("ObjectIdentifier", "")
        props = obj.get("Properties", {})
        name = props.get("name", "")

        if sid:
            result["groups"][sid] = obj
            if name:
                result["sid_to_name"][sid] = name
            result["sid_to_type"][sid] = "Group"

        # Build membership maps
        for member in obj.get("Members", []):
            member_sid = member.get("ObjectIdentifier", "")
            member_type = member.get("ObjectType", "")
            if member_sid:
                result["group_memberships"][sid].append(member_sid)
                result["reverse_memberships"][member_sid].append(sid)
                if member_sid not in result["sid_to_type"] and member_type:
                    result["sid_to_type"][member_sid] = member_type

        # Collect ACEs
        for ace in obj.get("Aces", []):
            ace["TargetSID"] = sid
            ace["TargetType"] = "Group"
            ace["TargetName"] = name
            result["aces"].append(ace)


def _process_computers(objects: list, result: dict):
    """Process computer objects."""
    for obj in objects:
        sid = obj.get("ObjectIdentifier", "")
        props = obj.get("Properties", {})
        name = props.get("name", "")

        if sid:
            result["computers"][sid] = obj
            if name:
                result["sid_to_name"][sid] = name
            result["sid_to_type"][sid] = "Computer"

        # Collect ACEs
        for ace in obj.get("Aces", []):
            ace["TargetSID"] = sid
            ace["TargetType"] = "Computer"
            ace["TargetName"] = name
            result["aces"].append(ace)


def _process_domains(objects: list, result: dict):
    """Process domain objects."""
    for obj in objects:
        sid = obj.get("ObjectIdentifier", "")
        props = obj.get("Properties", {})
        name = props.get("name", "")

        if not result["domain"]:
            result["domain"] = obj

        if sid:
            result["sid_to_name"][sid] = name
            result["sid_to_type"][sid] = "Domain"

        # Collect ACEs (important for DCSync detection)
        for ace in obj.get("Aces", []):
            ace["TargetSID"] = sid
            ace["TargetType"] = "Domain"
            ace["TargetName"] = name
            result["aces"].append(ace)


def _process_gpos(objects: list, result: dict):
    """Process GPO objects."""
    for obj in objects:
        oid = obj.get("ObjectIdentifier", "")
        props = obj.get("Properties", {})
        name = props.get("name", "")

        if oid:
            result["gpos"][oid] = obj
            result["sid_to_name"][oid] = name
            result["sid_to_type"][oid] = "GPO"

        # Collect ACEs
        for ace in obj.get("Aces", []):
            ace["TargetSID"] = oid
            ace["TargetType"] = "GPO"
            ace["TargetName"] = name
            result["aces"].append(ace)


def _process_ous(objects: list, result: dict):
    """Process OU objects."""
    for obj in objects:
        oid = obj.get("ObjectIdentifier", "")
        props = obj.get("Properties", {})
        name = props.get("name", "")

        if oid:
            result["ous"][oid] = obj
            result["sid_to_name"][oid] = name
            result["sid_to_type"][oid] = "OU"

        for ace in obj.get("Aces", []):
            ace["TargetSID"] = oid
            ace["TargetType"] = "OU"
            ace["TargetName"] = name
            result["aces"].append(ace)


def _process_containers(objects: list, result: dict):
    """Process container objects."""
    for obj in objects:
        oid = obj.get("ObjectIdentifier", "")
        props = obj.get("Properties", {})
        name = props.get("name", "")

        if oid:
            result["containers"][oid] = obj
            result["sid_to_name"][oid] = name
            result["sid_to_type"][oid] = "Container"

        for ace in obj.get("Aces", []):
            ace["TargetSID"] = oid
            ace["TargetType"] = "Container"
            ace["TargetName"] = name
            result["aces"].append(ace)


def _populate_wellknown_sids(result: dict):
    """Fill in names for well-known SIDs that weren't explicitly named."""
    domain_sid = ""
    if result["domain"]:
        domain_sid = result["domain"].get("Properties", {}).get("domainsid", "")
        domain_name = result["domain"].get("Properties", {}).get("name", "")

    for sid in list(result["sid_to_name"].keys()) + list(result["sid_to_type"].keys()):
        if sid in result["sid_to_name"] and result["sid_to_name"][sid]:
            continue

        # Check well-known full SIDs
        if sid in WELL_KNOWN_SIDS:
            result["sid_to_name"][sid] = WELL_KNOWN_SIDS[sid]
            continue

        # Check domain-relative SIDs (e.g., DOMAIN-S-1-5-32-544)
        if domain_sid and sid.startswith(domain_sid + "-"):
            rid = sid.split("-")[-1]
            if rid in WELL_KNOWN_RIDS:
                result["sid_to_name"][sid] = WELL_KNOWN_RIDS[rid]
                continue

        # Check builtin SIDs like DOMAIN-S-1-5-32-544
        parts = sid.split("-")
        if len(parts) >= 2:
            rid = parts[-1]
            if rid in WELL_KNOWN_RIDS:
                result["sid_to_name"][sid] = WELL_KNOWN_RIDS[rid]


def resolve_name(sid: str, result: dict) -> str:
    """Resolve a SID to a friendly name."""
    return result["sid_to_name"].get(sid, sid)


def get_domain_name(result: dict) -> str:
    """Get the domain name from parsed data."""
    if result["domain"]:
        return result["domain"].get("Properties", {}).get("name", "UNKNOWN")
    return "UNKNOWN"


def get_domain_sid(result: dict) -> str:
    """Get the domain SID."""
    if result["domain"]:
        return result["domain"].get("Properties", {}).get("domainsid", "")
    return ""
