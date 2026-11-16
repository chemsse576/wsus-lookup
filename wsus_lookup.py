#!/usr/bin/env python3
"""
WSUS GPO Targets - Finds machines targeted by WSUS GPOs
Looks up GPO links on OUs via LDAP, then lists computers in those OUs
"""

import argparse
import struct
import subprocess
import tempfile
import os
import sys


def ldap_query(server, domain, user, password, search_base, ldap_filter, attrs):
    """Run ldapsearch and return raw output"""
    cmd = [
        "ldapsearch", "-x", "-H", f"ldap://{server}",
        "-D", f"{user}@{domain}", "-w", password,
        "-b", search_base, ldap_filter
    ] + attrs
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        return ""
    return result.stdout


def get_wsus_gpos(server, domain, user, password):
    """Find GPOs with WindowsUpdate/WSUS in the name, return list of (name, guid)"""
    base_dn = ",".join(f"DC={p}" for p in domain.split("."))
    search_base = f"CN=Policies,CN=System,{base_dn}"
    out = ldap_query(server, domain, user, password, search_base,
                     "(objectClass=groupPolicyContainer)", ["displayName", "cn"])

    gpos, current = [], {}
    for line in out.splitlines():
        if line.startswith("displayName:"):
            current["name"] = line.split(":", 1)[1].strip()
        elif line.startswith("cn:"):
            current["guid"] = line.split(":", 1)[1].strip()
        elif line == "" and current:
            if "name" in current and "guid" in current:
                gpos.append(current)
            current = {}
    if current and "name" in current:
        gpos.append(current)

    keywords = ["windowsupdate", "wsus", "windows_update", "wupdate"]
    return [g for g in gpos if any(k in g.get("name", "").lower().replace(" ", "") for k in keywords)]


def find_gpo_links(server, domain, user, password, gpo_guid):
    """Find all OUs/containers where this GPO is linked via gPLink attribute"""
    base_dn = ",".join(f"DC={p}" for p in domain.split("."))
    # gPLink contains the GPO DN in the format [LDAP://cn={GUID},...;status]
    ldap_filter = f"(gPLink=*{gpo_guid}*)"
    out = ldap_query(server, domain, user, password, base_dn, ldap_filter, ["dn"])

    ous = []
    for line in out.splitlines():
        if line.startswith("dn:"):
            dn = line.split(":", 1)[1].strip()
            ous.append(dn)
    return ous


def get_computers_in_ou(server, domain, user, password, ou_dn):
    """List all computer objects under an OU (subtree search)"""
    out = ldap_query(server, domain, user, password, ou_dn,
                     "(objectClass=computer)", ["cn", "dNSHostName", "operatingSystem"])

    computers, current = [], {}
    for line in out.splitlines():
        if line.startswith("cn:"):
            current["name"] = line.split(":", 1)[1].strip()
        elif line.startswith("dNSHostName:"):
            current["dns"] = line.split(":", 1)[1].strip()
        elif line.startswith("operatingSystem:"):
            current["os"] = line.split(":", 1)[1].strip()
        elif line == "" and current:
            if "name" in current:
                computers.append(current)
            current = {}
    if current and "name" in current:
        computers.append(current)
    return computers


def download_registry_pol(server, domain, user, password, gpo_guid, tmpdir):
    remote_path = f"{domain}\\Policies\\{gpo_guid}\\Machine\\Registry.pol"
    local_path = os.path.join(tmpdir, f"{gpo_guid}.pol")
    cmd = [
        "smbclient", f"//{server}/SYSVOL",
        "-U", f"{user}%{password}",
        "-c", f"get {remote_path} {local_path}"
    ]
    subprocess.run(cmd, capture_output=True, text=True)
    if os.path.exists(local_path) and os.path.getsize(local_path) > 8:
        return local_path
    return None


def parse_registry_pol(filepath):
    with open(filepath, "rb") as f:
        data = f.read()
    if data[:4] != b"PReg":
        return []
    entries = []
    i = 8
    while i < len(data) - 2:
        if data[i:i+2] != b"\x5b\x00":
            i += 2
            continue
        i += 2
        sep = data.find(b"\x3b\x00", i)
        if sep == -1:
            break
        key = data[i:sep].decode("utf-16-le", errors="ignore").rstrip("\x00")
        i = sep + 2
        sep = data.find(b"\x3b\x00", i)
        if sep == -1:
            break
        val_name = data[i:sep].decode("utf-16-le", errors="ignore").rstrip("\x00")
        i = sep + 2
        if i + 4 > len(data):
            break
        reg_type = struct.unpack("<I", data[i:i+4])[0]
        i += 4
        if i + 2 > len(data):
            break
        i += 2
        if i + 4 > len(data):
            break
        data_size = struct.unpack("<I", data[i:i+4])[0]
        i += 4
        if i + 2 > len(data):
            break
        i += 2
        if i + data_size > len(data):
            break
        raw = data[i:i+data_size]
        i += data_size
        if i + 2 <= len(data) and data[i:i+2] == b"\x5d\x00":
            i += 2
        if reg_type == 1:
            val = raw.decode("utf-16-le", errors="ignore").rstrip("\x00")
        elif reg_type == 4:
            val = str(struct.unpack("<I", raw[:4])[0]) if len(raw) >= 4 else "?"
        else:
            val = raw.hex()
        entries.append({"key": key, "name": val_name, "value": val})
    return entries


def get_wsus_info(server, domain, user, password, gpo_guid, tmpdir):
    """Download and parse Registry.pol, return WSUS settings dict"""
    pol = download_registry_pol(server, domain, user, password, gpo_guid, tmpdir)
    if not pol:
        return {}
    entries = parse_registry_pol(pol)
    return {e["name"].lower(): e["value"] for e in entries if "windowsupdate" in e["key"].lower()}


def main():
    p = argparse.ArgumentParser(description="WSUS GPO Targets - Find machines targeted by WSUS GPOs")
    p.add_argument("-s", "--server", required=True, help="DC IP")
    p.add_argument("-d", "--domain", required=True, help="Domain FQDN")
    p.add_argument("-u", "--user", required=True, help="Username")
    p.add_argument("-p", "--password", required=True, help="Password")
    p.add_argument("-o", "--output", default="wsus_targets.txt", help="Output file (default: wsus_targets.txt)")
    args = p.parse_args()

    BOLD = "\033[1m"
    CYAN = "\033[96m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    DIM = "\033[2m"
    RST = "\033[0m"

    print(f"\n{BOLD}[*] WSUS GPO Targets{RST}")
    print(f"    Domain: {args.domain} | DC: {args.server}\n")

    wsus_gpos = get_wsus_gpos(args.server, args.domain, args.user, args.password)
    if not wsus_gpos:
        print("[-] No WSUS GPO found.")
        return

    print(f"[*] {len(wsus_gpos)} WSUS GPO(s) found\n")

    all_computers = {}
    gpo_details = []

    with tempfile.TemporaryDirectory() as tmpdir:
        for gpo in wsus_gpos:
            guid = gpo["guid"]
            name = gpo["name"]

            # Get WSUS config from Registry.pol
            wsus = get_wsus_info(args.server, args.domain, args.user, args.password, guid, tmpdir)

            # Find linked OUs
            ous = find_gpo_links(args.server, args.domain, args.user, args.password, guid)

            print(f"  {BOLD}{CYAN}{name}{RST}")

            # Show WSUS server URL
            wu_server = wsus.get("wuserver", "")
            if wu_server:
                if wu_server.lower().startswith("http://"):
                    print(f"    Server    : {RED}{wu_server} [HTTP]{RST}")
                elif wu_server.lower().startswith("https://"):
                    print(f"    Server    : {GREEN}{wu_server} [HTTPS]{RST}")
                else:
                    print(f"    Server    : {wu_server}")

            # Detection frequency
            freq = wsus.get("detectionfrequency", "")
            freq_on = wsus.get("detectionfrequencyenabled", "0")
            if freq and freq_on == "1":
                h = int(freq)
                print(f"    Detection : every {h}h")

            # Install schedule
            day = wsus.get("scheduledinstallday", "")
            hour = wsus.get("scheduledinstalltime", "")
            if day and hour:
                days = {0: "Every day", 1: "Sun", 2: "Mon", 3: "Tue", 4: "Wed", 5: "Thu", 6: "Fri", 7: "Sat"}
                print(f"    Install   : {days.get(int(day), day)} at {int(hour):02d}:00")

            # Target group
            group = wsus.get("targetgroup", "")
            if group:
                print(f"    Group     : {group}")

            # Linked OUs and machines
            if not ous:
                print(f"    {DIM}Not linked to any OU{RST}\n")
                continue

            gpo_machines = []
            for ou in ous:
                ou_short = ou.split(",")[0]
                computers = get_computers_in_ou(args.server, args.domain, args.user, args.password, ou)
                print(f"    {ou_short}: {BOLD}{len(computers)}{RST} machine(s)")
                for c in computers:
                    hostname = c.get("dns", c.get("name", "?"))
                    os_info = c.get("os", "")
                    all_computers[hostname] = os_info
                    gpo_machines.append(hostname)

            gpo_details.append({"name": name, "server": wu_server, "ous": ous, "machines": gpo_machines})
            print()

    if all_computers:
        with open(args.output, "w") as f:
            for host in sorted(all_computers.keys()):
                f.write(f"{host}\n")

        detail_file = args.output.rsplit(".", 1)[0] + "_detail.txt"
        with open(detail_file, "w") as f:
            f.write(f"# WSUS Targets - {args.domain}\n")
            f.write(f"# {len(all_computers)} unique machines\n\n")
            for gpo in gpo_details:
                f.write(f"## {gpo['name']}")
                if gpo.get("server"):
                    proto = "HTTP" if gpo["server"].lower().startswith("http://") else "HTTPS"
                    f.write(f" | {gpo['server']} [{proto}]")
                f.write("\n")
                for ou in gpo["ous"]:
                    f.write(f"  OU: {ou}\n")
                for m in sorted(gpo["machines"]):
                    os_info = all_computers.get(m, "")
                    line = f"  {m}"
                    if os_info:
                        line += f"  ({os_info})"
                    f.write(line + "\n")
                f.write("\n")

        print(f"{BOLD}[+] {len(all_computers)} unique machines{RST}")
        print(f"    Targets  : {args.output}")
        print(f"    Details  : {detail_file}")
    else:
        print("[-] No machines found in linked OUs.")

    print()


if __name__ == "__main__":
    main()
