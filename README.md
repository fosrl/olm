# Olm

Olm is a [WireGuard](https://www.wireguard.com/) tunnel client designed to securely connect your computer to Newt sites running on remote networks.

### Installation and Documentation

Olm is used with Pangolin and Newt as part of the larger system. See documentation below:

-   [Full Documentation](https://docs.pangolin.net/manage/clients/add-client)

## Key Functions

### Registers with Pangolin

Using the Olm ID and a secret, the olm will make HTTP requests to Pangolin to receive a session token. Using that token, it will connect to a websocket and maintain that connection. Control messages will be sent over the websocket.

### Receives WireGuard Control Messages

When Olm receives WireGuard control messages, it will use the information encoded (endpoint, public key) to bring up a WireGuard tunnel on your computer to a remote Newt. It will ping over the tunnel to ensure the peer is brought up.

## Hole Punching

In the default mode, olm uses both relaying through Gerbil and NAT hole punching to connect to newt. If you want to disable hole punching, use the `--disable-holepunch` flag. Hole punching attempts to orchestrate a NAT hole punch between the two sites so that traffic flows directly, which can save data costs and improve speed. If hole punching fails, traffic will fall back to relaying through Gerbil.

Right now, basic NAT hole punching is supported. We plan to add:

-   [ ] Birthday paradox
-   [ ] UPnP
-   [ ] LAN detection

## Build

### Binary

Make sure to have Go 1.25 installed.

```bash
make
```

## Licensing

Olm is dual licensed under the AGPLv3 and the Fossorial Commercial license. For inquiries about commercial licensing, please contact us.

## Contributions

Please see [CONTRIBUTIONS](./CONTRIBUTING.md) in the repository for guidelines and best practices.
