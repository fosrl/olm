#!/bin/bash

# Configuration
NS_NAME="isolated_ns"       # Name of the namespace
VETH_HOST="veth_host"       # Interface name on host side
VETH_NS="veth_ns"           # Interface name inside namespace
HOST_IP="192.168.15.1"      # Gateway IP for the namespace (host side)
NS_IP="192.168.15.2"        # IP address for the namespace
SUBNET_CIDR="24"            # Subnet mask
DNS_SERVER="8.8.8.8"        # DNS to use inside namespace

# Detect the main physical interface (gateway to internet)
PHY_IFACE=$(ip route get 8.8.8.8 | awk -- '{printf $5}')

# Helper function to check for root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "Error: This script must be run as root."
        exit 1
    fi
}

setup_ns() {
    echo "Bringing up namespace '$NS_NAME'..."

    # 1. Create the network namespace
    if ip netns list | grep -q "$NS_NAME"; then
        echo "Namespace $NS_NAME already exists. Run 'down' first."
        exit 1
    fi
    ip netns add "$NS_NAME"

    # 2. Create veth pair
    ip link add "$VETH_HOST" type veth peer name "$VETH_NS"

    # 3. Move peer interface to namespace
    ip link set "$VETH_NS" netns "$NS_NAME"

    # 4. Configure Host Side Interface
    ip addr add "${HOST_IP}/${SUBNET_CIDR}" dev "$VETH_HOST"
    ip link set "$VETH_HOST" up

    # 5. Configure Namespace Side Interface
    ip netns exec "$NS_NAME" ip addr add "${NS_IP}/${SUBNET_CIDR}" dev "$VETH_NS"
    ip netns exec "$NS_NAME" ip link set "$VETH_NS" up
    
    # 6. Bring up loopback inside namespace (crucial for many apps)
    ip netns exec "$NS_NAME" ip link set lo up

    # 7. Routing: Add default gateway inside namespace pointing to host
    ip netns exec "$NS_NAME" ip route add default via "$HOST_IP"

    # 8. Enable IP forwarding on host
    echo 1 > /proc/sys/net/ipv4/ip_forward

    # 9. NAT/Masquerade: Allow traffic from namespace to go out physical interface
    # We verify rule doesn't exist first to avoid duplicates
    iptables -t nat -C POSTROUTING -s "${NS_IP}/${SUBNET_CIDR}" -o "$PHY_IFACE" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s "${NS_IP}/${SUBNET_CIDR}" -o "$PHY_IFACE" -j MASQUERADE

    # Allow forwarding from host veth to WAN and back
    iptables -C FORWARD -i "$VETH_HOST" -o "$PHY_IFACE" -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i "$VETH_HOST" -o "$PHY_IFACE" -j ACCEPT

    iptables -C FORWARD -i "$PHY_IFACE" -o "$VETH_HOST" -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i "$PHY_IFACE" -o "$VETH_HOST" -j ACCEPT

    # 10. DNS Setup
    # Netns uses /etc/netns/<name>/resolv.conf if it exists
    mkdir -p "/etc/netns/$NS_NAME"
    echo "nameserver $DNS_SERVER" > "/etc/netns/$NS_NAME/resolv.conf"

    echo "Namespace $NS_NAME is UP."
    echo "To enter shell: sudo ip netns exec $NS_NAME bash"
}

teardown_ns() {
    echo "Tearing down namespace '$NS_NAME'..."

    # 1. Remove Namespace (this automatically deletes the veth pair inside it)
    # The host side veth usually disappears when the peer is destroyed.
    if ip netns list | grep -q "$NS_NAME"; then
        ip netns del "$NS_NAME"
    else
        echo "Namespace $NS_NAME does not exist."
    fi

    # 2. Clean up veth host side if it still lingers
    if ip link show "$VETH_HOST" > /dev/null 2>&1; then
        ip link delete "$VETH_HOST"
    fi

    # 3. Remove iptables rules
    # We use -D to delete the specific rules we added
    iptables -t nat -D POSTROUTING -s "${NS_IP}/${SUBNET_CIDR}" -o "$PHY_IFACE" -j MASQUERADE 2>/dev/null
    iptables -D FORWARD -i "$VETH_HOST" -o "$PHY_IFACE" -j ACCEPT 2>/dev/null
    iptables -D FORWARD -i "$PHY_IFACE" -o "$VETH_HOST" -j ACCEPT 2>/dev/null

    # 4. Remove DNS config
    rm -rf "/etc/netns/$NS_NAME"

    echo "Namespace $NS_NAME is DOWN."
}

test_connectivity() {
    echo "Testing connectivity inside $NS_NAME..."
    ip netns exec "$NS_NAME" ping -c 3 8.8.8.8
}

# Main execution logic
check_root

case "$1" in
    up)
        setup_ns
        ;;
    down)
        teardown_ns
        ;;
    test)
        test_connectivity
        ;;
    *)
        echo "Usage: $0 {up|down|test}"
        exit 1
esac