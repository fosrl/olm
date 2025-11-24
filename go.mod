module github.com/fosrl/olm

go 1.25

require (
	github.com/Microsoft/go-winio v0.6.2
	github.com/fosrl/newt v0.0.0
	github.com/gorilla/websocket v1.5.3
	github.com/miekg/dns v1.1.68
	github.com/vishvananda/netlink v1.3.1
	golang.org/x/sys v0.38.0
	golang.zx2c4.com/wireguard v0.0.0-20250521234502-f333402bd9cb
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20241231184526-a9ab2273dd10
	gvisor.dev/gvisor v0.0.0-20250503011706-39ed1f5ac29c
	software.sslmate.com/src/go-pkcs12 v0.6.0
)

require (
	github.com/godbus/dbus/v5 v5.2.0 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	golang.org/x/crypto v0.44.0 // indirect
	golang.org/x/exp v0.0.0-20251113190631-e25ba8c21ef6 // indirect
	golang.org/x/mod v0.30.0 // indirect
	golang.org/x/net v0.47.0 // indirect
	golang.org/x/sync v0.18.0 // indirect
	golang.org/x/time v0.12.0 // indirect
	golang.org/x/tools v0.39.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)

replace github.com/fosrl/newt => ../newt
