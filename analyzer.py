"""
analyzer.py — Static Analysis Engine for BloodHound Data

Identifies AD vulnerabilities, misconfigurations, and privilege escalation
paths without requiring AI. Produces structured findings for the AI engine.
"""

from collections import defaultdict
from parser import resolve_name, get_domain_name, get_domain_sid

# Dangerous ACL rights that indicate exploitable permissions
DANGEROUS_RIGHTS = {
    "GenericAll", "GenericWrite", "WriteDacl", "WriteOwner",
    "ForceChangePassword", "AddMember", "AllExtendedRights",
    "AddSelf", "WriteSPN", "AddKeyCredentialLink",
}

# Extended rights for BFS pathfinding (includes credential-access edges)
PATHFINDER_RIGHTS = DANGEROUS_RIGHTS | {
    "Owns", "ReadGMSAPassword", "ReadLAPSPassword",
    "AddAllowedToAct", "WriteAccountRestrictions",
}

# Well-known local group SID suffixes for AdminTo/CanRDP/etc. edges
LOCAL_ADMIN_SID_SUFFIX = "-544"       # Administrators
LOCAL_RDP_SID_SUFFIX = "-555"         # Remote Desktop Users
LOCAL_DCOM_SID_SUFFIX = "-562"        # Distributed COM Users
LOCAL_PSREMOTE_SID_SUFFIX = "-580"    # Remote Management Users

# High-value domain group RIDs (appended to {domain_sid}-RID)
HIGH_VALUE_DOMAIN_RIDS = {"512", "516", "518", "519"}

# High-value builtin group RIDs (use DOMAIN-S-1-5-32-RID format)
HIGH_VALUE_BUILTIN_RIDS = {"544", "548", "549", "551"}

# Combined set for backward compatibility
HIGH_VALUE_RIDS = HIGH_VALUE_DOMAIN_RIDS | HIGH_VALUE_BUILTIN_RIDS

# Well-known builtin/default SIDs to exclude from "interesting" findings
BUILTIN_PRINCIPAL_PATTERNS = {
    "-512",   # Domain Admins
    "-519",   # Enterprise Admins
    "-518",   # Schema Admins
    "-516",   # Domain Controllers
    "S-1-5-18",  # SYSTEM
    "S-1-5-9",   # Enterprise Domain Controllers
}


def run_all_checks(data: dict, owned_users: list = None) -> dict:
    """
    Run all static analysis checks on parsed BloodHound data.

    Args:
        data: Parsed BloodHound data from parser.parse_zip()
        owned_users: List of owned usernames (e.g., ["Ravindu.Lakmina", "K.Dennings"])

    Returns:
        dict with categorized findings
    """
    findings = {
        "domain_overview": _domain_overview(data),
        "domain_admins": _find_domain_admins(data),
        "high_value_groups": _find_high_value_groups(data),
        "kerberoastable": _find_kerberoastable(data),
        "asreproastable": _find_asreproastable(data),
        "password_never_expires": _find_pwd_never_expires(data),
        "unconstrained_delegation": _find_unconstrained_delegation(data),
        "constrained_delegation": _find_constrained_delegation(data),
        "dangerous_acls": _find_dangerous_acls(data),
        "dcsync_rights": _find_dcsync_rights(data),
        "gpo_abuse": _find_gpo_abuse(data),
        "stale_accounts": _find_stale_accounts(data),
        "privileged_users_summary": _privileged_users_summary(data),
    }

    # Privesc paths — run for each owned user
    if owned_users:
        all_paths = []
        errors = []
        for user in owned_users:
            owned_sid = _resolve_user_to_sid(data, user)
            if owned_sid:
                result = _find_privesc_paths(data, owned_sid)
                # Tag each path with the source user
                for path in result.get("paths", []):
                    path["from_user"] = user
                all_paths.extend(result.get("paths", []))
            else:
                errors.append(f"Could not resolve owned user '{user}' to a SID")

        # Sort all paths by number of hops
        all_paths.sort(key=lambda p: p["hops"])

        findings["privesc_paths"] = {
            "paths": all_paths,
            "count": len(all_paths),
        }
        if errors:
            findings["privesc_paths"]["errors"] = errors

    return findings



def _domain_overview(data: dict) -> dict:
    """Generate domain overview statistics."""
    domain = data.get("domain", {})
    props = domain.get("Properties", {}) if domain else {}

    return {
        "domain_name": props.get("name", "UNKNOWN"),
        "domain_sid": props.get("domainsid", ""),
        "functional_level": props.get("functionallevel", "Unknown"),
        "total_users": len(data["users"]),
        "total_groups": len(data["groups"]),
        "total_computers": len(data["computers"]),
        "total_gpos": len(data["gpos"]),
        "total_ous": len(data["ous"]),
        "enabled_users": sum(
            1 for u in data["users"].values()
            if u.get("Properties", {}).get("enabled", False)
        ),
        "disabled_users": sum(
            1 for u in data["users"].values()
            if not u.get("Properties", {}).get("enabled", True)
        ),
    }


def _find_domain_admins(data: dict) -> dict:
    """Find all Domain Admins and their nested members."""
    domain_sid = get_domain_sid(data)
    da_sid = f"{domain_sid}-512" if domain_sid else None

    result = {"direct_members": [], "nested_members": [], "group_sid": da_sid}

    if not da_sid or da_sid not in data["groups"]:
        # Try to find by name
        for sid, grp in data["groups"].items():
            name = grp.get("Properties", {}).get("name", "").upper()
            if "DOMAIN ADMINS" in name:
                da_sid = sid
                result["group_sid"] = da_sid
                break

    if not da_sid:
        return result

    # Direct members
    for member_sid in data["group_memberships"].get(da_sid, []):
        member_name = resolve_name(member_sid, data)
        member_type = data["sid_to_type"].get(member_sid, "Unknown")
        result["direct_members"].append({
            "sid": member_sid,
            "name": member_name,
            "type": member_type,
        })

    # Recursively resolve nested group members
    visited = set()
    _resolve_nested_members(data, da_sid, result["nested_members"], visited)

    return result


def _resolve_nested_members(data: dict, group_sid: str, members: list, visited: set, depth: int = 0):
    """Recursively resolve nested group members."""
    if group_sid in visited or depth > 10:
        return
    visited.add(group_sid)

    for member_sid in data["group_memberships"].get(group_sid, []):
        member_type = data["sid_to_type"].get(member_sid, "Unknown")
        member_name = resolve_name(member_sid, data)

        if member_type == "Group":
            _resolve_nested_members(data, member_sid, members, visited, depth + 1)
        else:
            if not any(m["sid"] == member_sid for m in members):
                members.append({
                    "sid": member_sid,
                    "name": member_name,
                    "type": member_type,
                    "via_group": resolve_name(group_sid, data),
                })


def _find_high_value_groups(data: dict) -> list:
    """Find all high-value groups and their members."""
    results = []
    for sid, grp in data["groups"].items():
        props = grp.get("Properties", {})
        if props.get("highvalue", False):
            members = []
            for member_sid in data["group_memberships"].get(sid, []):
                members.append({
                    "sid": member_sid,
                    "name": resolve_name(member_sid, data),
                    "type": data["sid_to_type"].get(member_sid, "Unknown"),
                })
            results.append({
                "sid": sid,
                "name": props.get("name", sid),
                "member_count": len(members),
                "members": members,
            })
    return results


def _find_kerberoastable(data: dict) -> dict:
    """Find Kerberoastable user accounts."""
    users = []
    for sid, user in data["users"].items():
        props = user.get("Properties", {})
        if props.get("hasspn", False) and props.get("enabled", False):
            spns = user.get("SPNTargets", [])
            users.append({
                "sid": sid,
                "name": props.get("name", sid),
                "spns": [s.get("Service", "") for s in spns] if spns else [],
                "admincount": props.get("admincount", False),
                "description": props.get("description", ""),
            })
    return {"users": users, "count": len(users)}


def _find_asreproastable(data: dict) -> dict:
    """Find AS-REP Roastable user accounts."""
    users = []
    for sid, user in data["users"].items():
        props = user.get("Properties", {})
        if props.get("dontreqpreauth", False):
            users.append({
                "sid": sid,
                "name": props.get("name", sid),
                "enabled": props.get("enabled", False),
                "admincount": props.get("admincount", False),
            })
    return {"users": users, "count": len(users)}


def _find_pwd_never_expires(data: dict) -> dict:
    """Find enabled accounts with 'Password Never Expires' set."""
    users = []
    for sid, user in data["users"].items():
        props = user.get("Properties", {})
        if (props.get("pwdneverexpires", False) and
                props.get("enabled", False) and
                props.get("name", "").upper() not in ("KRBTGT@", "ADMINISTRATOR@")):
            name = props.get("name", sid)
            # Skip krbtgt and well-known service accounts
            if "KRBTGT" in name.upper():
                continue
            users.append({
                "sid": sid,
                "name": name,
                "admincount": props.get("admincount", False),
                "lastlogon": props.get("lastlogon", 0),
                "pwdlastset": props.get("pwdlastset", 0),
            })
    return {"users": users, "count": len(users)}


def _find_unconstrained_delegation(data: dict) -> dict:
    """Find objects with unconstrained delegation."""
    targets = []

    # Check computers
    for sid, comp in data["computers"].items():
        props = comp.get("Properties", {})
        if props.get("unconstraineddelegation", False):
            targets.append({
                "sid": sid,
                "name": props.get("name", sid),
                "type": "Computer",
                "os": props.get("operatingsystem", ""),
                "enabled": props.get("enabled", True),
            })

    # Check users (service accounts)
    for sid, user in data["users"].items():
        props = user.get("Properties", {})
        if props.get("unconstraineddelegation", False):
            targets.append({
                "sid": sid,
                "name": props.get("name", sid),
                "type": "User",
                "enabled": props.get("enabled", False),
            })

    return {"targets": targets, "count": len(targets)}


def _find_constrained_delegation(data: dict) -> dict:
    """Find objects with constrained delegation (AllowedToDelegate)."""
    entries = []

    for sid, user in data["users"].items():
        delegates = user.get("AllowedToDelegate", [])
        if delegates:
            props = user.get("Properties", {})
            entries.append({
                "sid": sid,
                "name": props.get("name", sid),
                "type": "User",
                "targets": delegates,
                "enabled": props.get("enabled", False),
            })

    for sid, comp in data["computers"].items():
        delegates = comp.get("AllowedToDelegate", [])
        if delegates:
            props = comp.get("Properties", {})
            entries.append({
                "sid": sid,
                "name": props.get("name", sid),
                "type": "Computer",
                "targets": delegates,
                "enabled": props.get("enabled", True),
            })

    return {"entries": entries, "count": len(entries)}


def _is_builtin_principal(sid: str) -> bool:
    """Check if a SID belongs to a built-in/default principal (expected to have rights)."""
    for pattern in BUILTIN_PRINCIPAL_PATTERNS:
        if sid.endswith(pattern) or sid == pattern:
            return True
    # Builtin groups: S-1-5-32-*
    if "-S-1-5-32-" in sid:
        return True
    return False


def _find_dangerous_acls(data: dict) -> dict:
    """Find dangerous ACL permissions on AD objects."""
    findings = []
    seen = set()

    for ace in data["aces"]:
        right = ace.get("RightName", "")
        principal_sid = ace.get("PrincipalSID", "")
        target_sid = ace.get("TargetSID", "")
        target_type = ace.get("TargetType", "")
        target_name = ace.get("TargetName", "")
        is_inherited = ace.get("IsInherited", False)

        # Only look for dangerous rights
        if right not in DANGEROUS_RIGHTS:
            continue

        # Skip builtin/expected permissions
        if _is_builtin_principal(principal_sid):
            continue

        # Skip self-referencing ACEs
        if principal_sid == target_sid:
            continue

        # Create unique key to avoid duplicates
        key = f"{principal_sid}|{right}|{target_sid}"
        if key in seen:
            continue
        seen.add(key)

        principal_name = resolve_name(principal_sid, data)
        principal_type = data["sid_to_type"].get(principal_sid, "Unknown")

        findings.append({
            "principal_sid": principal_sid,
            "principal_name": principal_name,
            "principal_type": principal_type,
            "right": right,
            "target_sid": target_sid,
            "target_name": target_name,
            "target_type": target_type,
            "is_inherited": is_inherited,
        })

    # Sort by severity: non-inherited first, then by right
    right_priority = {
        "GenericAll": 0, "WriteDacl": 1, "WriteOwner": 2,
        "AllExtendedRights": 3, "GenericWrite": 4, "ForceChangePassword": 5,
        "AddMember": 6, "WriteSPN": 7, "AddKeyCredentialLink": 8, "AddSelf": 9,
    }
    findings.sort(key=lambda f: (f["is_inherited"], right_priority.get(f["right"], 99)))

    return {"acls": findings, "count": len(findings)}


def _find_dcsync_rights(data: dict) -> dict:
    """Find principals with DCSync rights (GetChanges + GetChangesAll on domain)."""
    domain_sid = get_domain_sid(data)
    if not domain_sid:
        return {"principals": [], "count": 0}

    # Collect who has GetChanges and GetChangesAll on the domain object
    get_changes = set()
    get_changes_all = set()

    for ace in data["aces"]:
        if ace.get("TargetType") != "Domain":
            continue

        right = ace.get("RightName", "")
        principal = ace.get("PrincipalSID", "")

        if right == "GetChanges":
            get_changes.add(principal)
        elif right == "GetChangesAll":
            get_changes_all.add(principal)
        elif right == "AllExtendedRights":
            # AllExtendedRights implies both
            get_changes.add(principal)
            get_changes_all.add(principal)

    # DCSync = both GetChanges AND GetChangesAll
    dcsync_sids = get_changes & get_changes_all

    principals = []
    for sid in dcsync_sids:
        # Skip expected principals (Domain Controllers, etc.)
        if _is_builtin_principal(sid):
            continue

        name = resolve_name(sid, data)
        obj_type = data["sid_to_type"].get(sid, "Unknown")
        principals.append({
            "sid": sid,
            "name": name,
            "type": obj_type,
        })

    return {"principals": principals, "count": len(principals)}


def _find_gpo_abuse(data: dict) -> dict:
    """Find GPOs where non-admin principals have write access."""
    findings = []

    for oid, gpo in data["gpos"].items():
        props = gpo.get("Properties", {})
        gpo_name = props.get("name", oid)

        for ace in gpo.get("Aces", []):
            right = ace.get("RightName", "")
            principal_sid = ace.get("PrincipalSID", "")

            if right not in ("GenericWrite", "GenericAll", "WriteDacl", "WriteOwner", "Owns"):
                continue

            if _is_builtin_principal(principal_sid):
                continue

            principal_name = resolve_name(principal_sid, data)
            principal_type = data["sid_to_type"].get(principal_sid, "Unknown")

            findings.append({
                "gpo_id": oid,
                "gpo_name": gpo_name,
                "gpo_path": props.get("gpcpath", ""),
                "principal_sid": principal_sid,
                "principal_name": principal_name,
                "principal_type": principal_type,
                "right": right,
            })

    return {"gpos": findings, "count": len(findings)}


def _find_stale_accounts(data: dict) -> dict:
    """Find disabled accounts still in privileged groups, or other stale indicators."""
    stale = []

    for sid, user in data["users"].items():
        props = user.get("Properties", {})
        enabled = props.get("enabled", True)
        name = props.get("name", sid)

        # Check if disabled user is in any group
        if not enabled:
            member_of = data["reverse_memberships"].get(sid, [])
            if member_of:
                group_names = [resolve_name(g, data) for g in member_of]
                stale.append({
                    "sid": sid,
                    "name": name,
                    "issue": "Disabled account in groups",
                    "groups": group_names,
                })

    return {"accounts": stale, "count": len(stale)}


def _privileged_users_summary(data: dict) -> dict:
    """Build a summary of all users with admin-like attributes."""
    privileged = []

    for sid, user in data["users"].items():
        props = user.get("Properties", {})
        if props.get("admincount", False) and props.get("enabled", False):
            name = props.get("name", sid)
            member_of = data["reverse_memberships"].get(sid, [])
            group_names = [resolve_name(g, data) for g in member_of]

            privileged.append({
                "sid": sid,
                "name": name,
                "groups": group_names,
                "hasspn": props.get("hasspn", False),
                "dontreqpreauth": props.get("dontreqpreauth", False),
            })

    return {"users": privileged, "count": len(privileged)}


def _resolve_user_to_sid(data: dict, username: str) -> str | None:
    """Resolve a username to its SID."""
    username_upper = username.upper().strip()

    for sid, user in data["users"].items():
        props = user.get("Properties", {})
        name = props.get("name", "").upper()
        sam = props.get("samaccountname", "").upper()

        if name == username_upper or sam == username_upper:
            return sid
        # Also match partial (without domain suffix)
        if "@" in name and name.split("@")[0] == username_upper:
            return sid
        if "@" in username_upper and username_upper.split("@")[0] == sam:
            return sid

    return None


def _find_privesc_paths(data: dict, owned_sid: str) -> dict:
    """
    Find privilege escalation paths from owned user to high-value targets
    using BFS through ACL chains, group memberships, local admin rights,
    RBCD (AllowedToAct), sessions, and credential-access edges.
    """
    domain_sid = get_domain_sid(data)

    # Define high-value target SIDs
    high_value_targets = set()
    for sid, grp in data["groups"].items():
        if grp.get("Properties", {}).get("highvalue", False):
            high_value_targets.add(sid)

    # Add well-known domain groups ({domain_sid}-RID)
    if domain_sid:
        for rid in HIGH_VALUE_DOMAIN_RIDS:
            high_value_targets.add(f"{domain_sid}-{rid}")

    # Add builtin groups: scan all group SIDs for builtin RID suffix patterns
    # BloodHound uses "DOMAIN-S-1-5-32-RID" format for builtin groups
    for sid in data["groups"]:
        for rid in HIGH_VALUE_BUILTIN_RIDS:
            if sid.endswith(f"-{rid}") and ("S-1-5-32" in sid or sid.endswith(f"-{rid}")):
                high_value_targets.add(sid)

    # Mark Domain Controllers as high-value targets
    for sid, comp in data["computers"].items():
        if comp.get("IsDC", False):
            high_value_targets.add(sid)

    # Build attack graph: edges represent exploitable relationships
    # edge = (source_sid, target_sid, relationship_type)
    attack_graph = defaultdict(list)

    # 1. Group membership edges: if user is in a group, they inherit the group's rights
    for group_sid, members in data["group_memberships"].items():
        for member_sid in members:
            attack_graph[member_sid].append((group_sid, "MemberOf"))

    # 2. ACL-based edges: expanded set including Owns, ReadGMSA, ReadLAPS, RBCD, etc.
    for ace in data["aces"]:
        right = ace.get("RightName", "")
        if right not in PATHFINDER_RIGHTS:
            continue

        principal_sid = ace.get("PrincipalSID", "")
        target_sid = ace.get("TargetSID", "")

        if principal_sid and target_sid and principal_sid != target_sid:
            attack_graph[principal_sid].append((target_sid, right))

    # 3. Computer-based edges from LocalGroups, AllowedToAct, etc.
    for comp_sid, comp in data["computers"].items():
        # AllowedToAct (Resource-Based Constrained Delegation)
        for entry in comp.get("AllowedToAct", []) or []:
            actor_sid = entry if isinstance(entry, str) else entry.get("ObjectIdentifier", "")
            if actor_sid:
                attack_graph[actor_sid].append((comp_sid, "AllowedToAct"))

        # LocalGroups: extract AdminTo, CanRDP, CanPSRemote, ExecuteDCOM
        local_groups = comp.get("LocalGroups", [])
        if isinstance(local_groups, dict):
            local_groups = local_groups.get("Results", [])
        for lg in local_groups or []:
            lg_sid = lg.get("ObjectIdentifier", "")
            results = lg.get("Results", [])
            if not results:
                continue

            # Determine relationship type from the local group SID suffix
            if lg_sid.endswith(LOCAL_ADMIN_SID_SUFFIX):
                rel_type = "AdminTo"
            elif lg_sid.endswith(LOCAL_RDP_SID_SUFFIX):
                rel_type = "CanRDP"
            elif lg_sid.endswith(LOCAL_PSREMOTE_SID_SUFFIX):
                rel_type = "CanPSRemote"
            elif lg_sid.endswith(LOCAL_DCOM_SID_SUFFIX):
                rel_type = "ExecuteDCOM"
            else:
                continue  # Skip non-exploitable local groups

            for member in results:
                member_sid = member.get("ObjectIdentifier", "")
                if member_sid and member_sid != comp_sid:
                    attack_graph[member_sid].append((comp_sid, rel_type))

    # 4. Implicit: MemberOf chains propagate through the graph during BFS

    # BFS from owned user
    paths = []
    queue = [(owned_sid, [(owned_sid, "START", resolve_name(owned_sid, data))])]
    visited = {owned_sid}
    max_depth = 8
    max_paths = 20

    while queue and len(paths) < max_paths:
        current_sid, path = queue.pop(0)

        if len(path) > max_depth:
            continue

        for next_sid, relationship in attack_graph.get(current_sid, []):
            if next_sid in visited:
                continue

            next_name = resolve_name(next_sid, data)
            new_path = path + [(next_sid, relationship, next_name)]

            if next_sid in high_value_targets:
                # Found a path to a high-value target!
                formatted_path = []
                for i in range(len(new_path) - 1):
                    from_sid, _, from_name = new_path[i]
                    to_sid, rel, to_name = new_path[i + 1]
                    formatted_path.append({
                        "from": from_name,
                        "from_sid": from_sid,
                        "via": rel,
                        "to": to_name,
                        "to_sid": to_sid,
                    })
                paths.append({
                    "target": next_name,
                    "target_sid": next_sid,
                    "hops": len(formatted_path),
                    "chain": formatted_path,
                })

            visited.add(next_sid)
            queue.append((next_sid, new_path))

    # Sort paths by number of hops (shortest first)
    paths.sort(key=lambda p: p["hops"])

    return {"paths": paths, "count": len(paths)}


def format_findings_for_ai(findings: dict, data: dict) -> str:
    """Format all findings into a text summary suitable for the AI prompt."""
    sections = []
    domain = findings.get("domain_overview", {})

    # Domain Overview
    sections.append(f"""### Domain Overview
- **Domain**: {domain.get('domain_name', 'N/A')}
- **Functional Level**: {domain.get('functional_level', 'N/A')}
- **Users**: {domain.get('total_users', 0)} ({domain.get('enabled_users', 0)} enabled, {domain.get('disabled_users', 0)} disabled)
- **Groups**: {domain.get('total_groups', 0)}
- **Computers**: {domain.get('total_computers', 0)}
- **GPOs**: {domain.get('total_gpos', 0)}""")

    # Domain Admins
    da = findings.get("domain_admins", {})
    if da.get("direct_members"):
        members = "\n".join(f"  - {m['name']} ({m['type']})" for m in da["direct_members"])
        sections.append(f"### Domain Admins\n**Direct Members**:\n{members}")

    # High Value Groups
    hvg = findings.get("high_value_groups", [])
    if hvg:
        lines = []
        for g in hvg:
            member_list = ", ".join(m["name"] for m in g["members"]) if g["members"] else "(empty)"
            lines.append(f"  - **{g['name']}** ({g['member_count']} members): {member_list}")
        sections.append(f"### High-Value Groups\n" + "\n".join(lines))

    # Kerberoastable
    kerb = findings.get("kerberoastable", {})
    if kerb.get("users"):
        users = "\n".join(
            f"  - **{u['name']}** (admincount: {u['admincount']})"
            for u in kerb["users"]
        )
        sections.append(f"### 🔥 Kerberoastable Accounts ({kerb['count']})\n{users}")

    # AS-REP Roastable
    asrep = findings.get("asreproastable", {})
    if asrep.get("users"):
        users = "\n".join(f"  - **{u['name']}** (enabled: {u['enabled']})" for u in asrep["users"])
        sections.append(f"### 🔥 AS-REP Roastable Accounts ({asrep['count']})\n{users}")

    # Password Never Expires
    pne = findings.get("password_never_expires", {})
    if pne.get("users"):
        users = "\n".join(f"  - {u['name']}" for u in pne["users"])
        sections.append(f"### ⚠️ Password Never Expires ({pne['count']})\n{users}")

    # Unconstrained Delegation
    ud = findings.get("unconstrained_delegation", {})
    if ud.get("targets"):
        targets = "\n".join(f"  - **{t['name']}** ({t['type']})" for t in ud["targets"])
        sections.append(f"### 🔥 Unconstrained Delegation ({ud['count']})\n{targets}")

    # Constrained Delegation
    cd = findings.get("constrained_delegation", {})
    if cd.get("entries"):
        entries = "\n".join(
            f"  - **{e['name']}** → {', '.join(e['targets'])}"
            for e in cd["entries"]
        )
        sections.append(f"### ⚠️ Constrained Delegation ({cd['count']})\n{entries}")

    # DCSync Rights
    dcs = findings.get("dcsync_rights", {})
    if dcs.get("principals"):
        principals = "\n".join(f"  - **{p['name']}** ({p['type']})" for p in dcs["principals"])
        sections.append(f"### 🔥 DCSync Rights ({dcs['count']})\n{principals}")

    # Dangerous ACLs
    dacl = findings.get("dangerous_acls", {})
    if dacl.get("acls"):
        lines = []
        for a in dacl["acls"][:30]:  # Limit to top 30
            lines.append(
                f"  - **{a['principal_name']}** ({a['principal_type']}) "
                f"→ [{a['right']}] → **{a['target_name']}** ({a['target_type']})"
                f"{' [inherited]' if a['is_inherited'] else ''}"
            )
        sections.append(
            f"### 🔥 Dangerous ACL Permissions ({dacl['count']})\n" + "\n".join(lines)
        )

    # GPO Abuse
    gpo = findings.get("gpo_abuse", {})
    if gpo.get("gpos"):
        lines = []
        for g in gpo["gpos"]:
            lines.append(
                f"  - **{g['principal_name']}** has [{g['right']}] on GPO **{g['gpo_name']}**"
            )
        sections.append(f"### ⚠️ GPO Abuse Opportunities ({gpo['count']})\n" + "\n".join(lines))

    # Stale Accounts
    stale = findings.get("stale_accounts", {})
    if stale.get("accounts"):
        lines = []
        for a in stale["accounts"]:
            lines.append(f"  - **{a['name']}** — {a['issue']} ({', '.join(a['groups'])})")
        sections.append(f"### ⚠️ Stale/Disabled Accounts ({stale['count']})\n" + "\n".join(lines))

    # Privilege Escalation Paths
    pe = findings.get("privesc_paths", {})
    if pe.get("paths"):
        lines = []
        for i, p in enumerate(pe["paths"][:10], 1):
            chain = " → ".join(
                f"{step['from']} --[{step['via']}]--> {step['to']}"
                for step in p["chain"]
            )
            lines.append(f"  **Path {i}** ({p['hops']} hops → **{p['target']}**):\n    {chain}")
        sections.append(
            f"### 🔥 Privilege Escalation Paths ({pe['count']})\n" + "\n\n".join(lines)
        )

    return "\n\n".join(sections)
