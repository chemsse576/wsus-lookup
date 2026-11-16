# WSUS GPO Targets

Enumerate machines targeted by WSUS Group Policy Objects in an Active Directory domain.

Queries LDAP for GPOs containing WSUS configuration, resolves their OU links, and lists all computer objects in those OUs. Also downloads and parses `Registry.pol` from SYSVOL to extract WSUS server URLs, update schedules, and target groups.

## Features

- Discovers WSUS-related GPOs by name pattern matching
- Parses `Registry.pol` binary format to extract WSUS settings (server URL, detection frequency, install schedule, target group)
- Highlights HTTP vs HTTPS WSUS endpoints (HTTP = potential for WSUS exploitation)
- Resolves GPO-to-OU links via `gPLink` attribute
- Enumerates all computers in linked OUs with OS info
- Outputs a clean target list + detailed report

## Requirements

- Python 3.6+
- `ldapsearch` (from `ldap-utils` / `openldap-clients`)
- `smbclient` (from `samba-client`)
- Valid domain credentials

```bash
# Kali / Debian
apt install ldap-utils smbclient
```

## Usage

```
python3 wsus_gpo_targets.py -s <DC_IP> -d <DOMAIN> -u <USER> -p <PASSWORD> [-o output.txt]
```

### Example

```
python3 wsus_gpo_targets.py -s 10.0.2.1 -d corp.local -u pentest -p 'P@ssw0rd'

[*] WSUS GPO Targets
    Domain: corp.local | DC: 10.0.2.1

[*] 2 WSUS GPO(s) found

  GPO-WSUS-Servers
    Server    : http://wsus.corp.local:8530 [HTTP]
    Detection : every 4h
    Install   : Wed at 03:00
    OU=Servers,DC=corp,DC=local: 42 machine(s)

  GPO-WindowsUpdate-Workstations
    Server    : https://wsus.corp.local:8531 [HTTPS]
    OU=Workstations,DC=corp,DC=local: 215 machine(s)

[+] 257 unique machines
    Targets  : wsus_targets.txt
    Details  : wsus_targets_detail.txt
```

### Output Files

- `wsus_targets.txt` - One hostname per line, ready for scanning
- `wsus_targets_detail.txt` - Full breakdown by GPO with OU mappings and OS info

## Why

During a pentest, identifying WSUS infrastructure matters:

- **HTTP WSUS** endpoints are vulnerable to MitM attacks ([WSUSpendu](https://github.com/AlsidOfficial/WSUSpect-proxy), [SharpWSUS](https://github.com/nettitude/SharpWSUS)) allowing malicious update injection
- Knowing which machines are managed by WSUS helps scope lateral movement targets
- WSUS target groups reveal network segmentation logic

## Disclaimer

This tool is intended for authorized security testing and educational purposes only. Unauthorized access to computer systems is illegal. Always obtain proper written authorization before testing.

## License

MIT
