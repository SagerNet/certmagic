package certmagic

import (
	"net"
	"strings"
	"sync"
	"time"
)

// Code in this file adapted from go-acme/lego, July 2020:
// https://github.com/go-acme/lego
// by Ludovic Fernandez and Dominik Menke
//
// It has been modified.

// findZoneByFQDN determines the zone apex for the given fqdn by recursing
// up the domain labels until the nameserver returns a SOA record in the
// answer section.
func findZoneByFQDN(fqdn string, nameservers []string) (string, error) {
	if !strings.HasSuffix(fqdn, ".") {
		fqdn += "."
	}
	soa, err := lookupSoaByFqdn(fqdn, nameservers)
	if err != nil {
		return "", err
	}
	return soa.zone, nil
}

func lookupSoaByFqdn(fqdn string, nameservers []string) (*soaCacheEntry, error) {
	if !strings.HasSuffix(fqdn, ".") {
		fqdn += "."
	}

	fqdnSOACacheMu.Lock()
	defer fqdnSOACacheMu.Unlock()

	// prefer cached version if fresh
	if ent := fqdnSOACache[fqdn]; ent != nil && !ent.isExpired() {
		return ent, nil
	}

	ent, err := fetchSoaByFqdn(fqdn, nameservers)
	if err != nil {
		return nil, err
	}

	// save result to cache, but don't allow
	// the cache to grow out of control
	if len(fqdnSOACache) >= 1000 {
		for key := range fqdnSOACache {
			delete(fqdnSOACache, key)
			break
		}
	}
	fqdnSOACache[fqdn] = ent

	return ent, nil
}

// soaCacheEntry holds a cached SOA record (only selected fields)
type soaCacheEntry struct {
	zone      string    // zone apex (a domain name)
	primaryNs string    // primary nameserver for the zone apex
	expires   time.Time // time when this cache entry should be evicted
}

// isExpired checks whether a cache entry should be considered expired.
func (cache *soaCacheEntry) isExpired() bool {
	return time.Now().After(cache.expires)
}

// populateNameserverPorts ensures that all nameservers have a port number.
func populateNameserverPorts(servers []string) {
	for i := range servers {
		_, port, _ := net.SplitHostPort(servers[i])
		if port == "" {
			servers[i] = net.JoinHostPort(servers[i], "53")
		}
	}
}

// recursiveNameservers are used to pre-check DNS propagation. It
// picks user-configured nameservers (custom) OR the defaults
// obtained from resolv.conf and defaultNameservers if none is
// configured and ensures that all server addresses have a port value.
func recursiveNameservers(custom []string) []string {
	var servers []string
	if len(custom) == 0 {
		servers = defaultNameservers
	} else {
		servers = make([]string, len(custom))
		copy(servers, custom)
	}
	populateNameserverPorts(servers)
	return servers
}

var defaultNameservers = []string{
	"8.8.8.8:53",
	"8.8.4.4:53",
	"1.1.1.1:53",
	"1.0.0.1:53",
}

var dnsTimeout = 10 * time.Second

var (
	fqdnSOACache   = map[string]*soaCacheEntry{}
	fqdnSOACacheMu sync.Mutex
)

const defaultResolvConf = "/etc/resolv.conf"
