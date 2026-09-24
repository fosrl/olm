package websocket

import (
	"strconv"
	"strings"
)

// minBatchedSiteMessagesVersion is the first pangolin server version that understands the
// batched siteIds/chainIds (and endpoints/relayEndpoints) form of the olm/wg/relay,
// olm/wg/unrelay, olm/wg/local and olm/wg/unlocal messages. Servers older than this only
// understand the singular siteId/chainId form, so olm must fall back to sending those
// messages one at a time.
const minBatchedSiteMessagesVersion = "1.24.0"

// SupportsBatchedSiteMessages reports whether the server we're connected to is new enough
// to understand batched relay/unrelay/local/unlocal messages, based on the serverVersion
// returned in the last token exchange.
func (c *Client) SupportsBatchedSiteMessages() bool {
	return supportsBatchedSiteMessages(c.ServerVersion())
}

// ServerVersion returns the version reported by the server during the last token exchange,
// or "" if unknown (e.g. no successful connection has completed yet).
func (c *Client) ServerVersion() string {
	c.tokenMux.RLock()
	defer c.tokenMux.RUnlock()
	return c.serverVersion
}

func supportsBatchedSiteMessages(serverVersion string) bool {
	if serverVersion == "" {
		// Unknown server version: assume it predates batching rather than risk sending a
		// format an old server can't parse.
		return false
	}
	return compareVersions(baseVersion(serverVersion), minBatchedSiteMessagesVersion) >= 0
}

// baseVersion strips any "-suffix" build metadata (e.g. "1.24.0-s.5" -> "1.24.0").
func baseVersion(v string) string {
	if i := strings.IndexByte(v, '-'); i >= 0 {
		return v[:i]
	}
	return v
}

// compareVersions compares two dotted numeric version strings (e.g. "1.24.0"), returning
// -1 if a < b, 0 if equal, or 1 if a > b. Missing or non-numeric components are treated as
// 0, so a partial or malformed version degrades gracefully instead of panicking.
func compareVersions(a, b string) int {
	as := strings.Split(a, ".")
	bs := strings.Split(b, ".")

	max := len(as)
	if len(bs) > max {
		max = len(bs)
	}

	for i := 0; i < max; i++ {
		var an, bn int
		if i < len(as) {
			an, _ = strconv.Atoi(as[i])
		}
		if i < len(bs) {
			bn, _ = strconv.Atoi(bs[i])
		}
		if an != bn {
			if an < bn {
				return -1
			}
			return 1
		}
	}
	return 0
}
