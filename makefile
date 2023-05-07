.PHONY: vpn-connection

vpn-connection:
	sudo openvpn sad.me.ovpn
stop:
	sudo killall openvpn
