//go:build !with_miekg_dns

package certmagic

import (
	"strings"
	"fmt"
	"time"
	"net"
	"errors"
	"golang.org/x/net/dns/dnsmessage"
	"github.com/sagernet/sing-dns"
	"context"
	"github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/metadata"
)

func dnsSplit(s string) []int {
	if s == "." {
		return nil
	}
	idx := make([]int, 1, 3)
	off := 0
	end := false

	for {
		off, end = dnsNextLabel(s, off)
		if end {
			return idx
		}
		idx = append(idx, off)
	}
}

func dnsNextLabel(s string, offset int) (i int, end bool) {
	if s == "" {
		return 0, true
	}
	for i = offset; i < len(s)-1; i++ {
		if s[i] != '.' {
			continue
		}
		j := i - 1
		for j >= 0 && s[j] == '\\' {
			j--
		}

		if (j-i)%2 == 0 {
			continue
		}

		return i + 1, false
	}
	return i + 1, true
}

func fetchSoaByFqdn(fqdn string, nameservers []string) (*soaCacheEntry, error) {
	var err error
	var in *dnsmessage.Message
	labelIndexes := dnsSplit(fqdn)
	for _, index := range labelIndexes {
		domain := fqdn[index:]

		in, err = dnsQuery(domain, dnsmessage.TypeSOA, nameservers, true)
		if err != nil {
			continue
		}
		if in == nil {
			continue
		}

		switch in.RCode {
		case dnsmessage.RCodeSuccess:
			// Check if we got a SOA RR in the answer section
			if len(in.Answers) == 0 {
				continue
			}

			// CNAME records cannot/should not exist at the root of a zone.
			// So we skip a domain when a CNAME is found.
			if dnsMsgContainsCNAME(in) {
				continue
			}

			for _, ans := range in.Answers {
				if soa, ok := ans.Body.(*dnsmessage.SOAResource); ok {
					return newSoaCacheEntry(ans.Header.Name.String(), soa), nil
				}
			}
		case dnsmessage.RCodeNameError:
			// NXDOMAIN
		default:
			// Any response code other than NOERROR and NXDOMAIN is treated as error
			return nil, fmt.Errorf("unexpected response code '%s' for %s", in.RCode.String(), domain)
		}
	}

	return nil, fmt.Errorf("could not find the start of authority for %s%s", fqdn, formatDNSError(in, err))
}

// dnsMsgContainsCNAME checks for a CNAME answer in msg
func dnsMsgContainsCNAME(msg *dnsmessage.Message) bool {
	for _, ans := range msg.Answers {
		if _, ok := ans.Body.(*dnsmessage.CNAMEResource); ok {
			return true
		}
	}
	return false
}

func dnsQuery(fqdn string, rtype dnsmessage.Type, nameservers []string, recursive bool) (*dnsmessage.Message, error) {
	m := createDNSMsg(fqdn, rtype, recursive)
	var in *dnsmessage.Message
	var err error
	for _, ns := range nameservers {
		in, err = sendDNSQuery(m, ns)
		if err == nil && len(in.Answers) > 0 {
			break
		}
	}
	return in, err
}

func createDNSMsg(fqdn string, rtype dnsmessage.Type, recursive bool) *dnsmessage.Message {
	m := new(dnsmessage.Message)
	m.Questions = []dnsmessage.Question{{Name: dnsmessage.MustNewName(fqdn), Type: rtype, Class: dnsmessage.ClassINET}}
	var edns0Hdr dnsmessage.ResourceHeader
	edns0Hdr.SetEDNS0(1232, 0, false)
	m.Additionals = append(m.Additionals, dnsmessage.Resource{Header: edns0Hdr})
	if !recursive {
		m.RecursionDesired = false
	}
	return m
}

func sendDNSQuery(m *dnsmessage.Message, ns string) (*dnsmessage.Message, error) {
	var client dns.Transport
	client = dns.NewUDPTransport(context.Background(), network.SystemDialer, metadata.ParseSocksaddr(ns))
	defer client.Close()
	resp, err := client.Exchange(context.Background(), m)
	if err == nil {
		return resp, nil
	}
	if err.Error() == "insufficient data for base length type" {
		client.Close()
		client = dns.NewTCPTransport(context.Background(), network.SystemDialer, metadata.ParseSocksaddr(ns))
	}
	return client.Exchange(context.Background(), m)
}

func formatDNSError(msg *dnsmessage.Message, err error) string {
	var parts []string
	if msg != nil {
		parts = append(parts, msg.RCode.String())
	}
	if err != nil {
		parts = append(parts, err.Error())
	}
	if len(parts) > 0 {
		return ": " + strings.Join(parts, " ")
	}
	return ""
}

func newSoaCacheEntry(zone string, soa *dnsmessage.SOAResource) *soaCacheEntry {
	return &soaCacheEntry{
		zone:      zone,
		primaryNs: soa.NS.String(),
		expires:   time.Now().Add(time.Duration(soa.Refresh) * time.Second),
	}
}

// checkDNSPropagation checks if the expected TXT record has been propagated to all authoritative nameservers.
func checkDNSPropagation(fqdn, value string, resolvers []string) (bool, error) {
	if !strings.HasSuffix(fqdn, ".") {
		fqdn += "."
	}

	// Initial attempt to resolve at the recursive NS
	r, err := dnsQuery(fqdn, dnsmessage.TypeTXT, resolvers, true)
	if err != nil {
		return false, err
	}

	if r.RCode == dnsmessage.RCodeSuccess {
		fqdn = updateDomainWithCName(r, fqdn)
	}

	authoritativeNss, err := lookupNameservers(fqdn, resolvers)
	if err != nil {
		return false, err
	}

	return checkAuthoritativeNss(fqdn, value, authoritativeNss)
}

// checkAuthoritativeNss queries each of the given nameservers for the expected TXT record.
func checkAuthoritativeNss(fqdn, value string, nameservers []string) (bool, error) {
	for _, ns := range nameservers {
		r, err := dnsQuery(fqdn, dnsmessage.TypeTXT, []string{net.JoinHostPort(ns, "53")}, false)
		if err != nil {
			return false, err
		}

		if r.RCode != dnsmessage.RCodeSuccess {
			if r.RCode == dnsmessage.RCodeNameError {
				// if Present() succeeded, then it must show up eventually, or else
				// something is really broken in the DNS provider or their API;
				// no need for error here, simply have the caller try again
				return false, nil
			}
			return false, fmt.Errorf("NS %s returned %s for %s", ns, r.RCode.String(), fqdn)
		}

		var found bool
		for _, rr := range r.Answers {
			if txt, ok := rr.Body.(*dnsmessage.TXTResource); ok {
				record := strings.Join(txt.TXT, "")
				if record == value {
					found = true
					break
				}
			}
		}

		if !found {
			return false, nil
		}
	}

	return true, nil
}

// lookupNameservers returns the authoritative nameservers for the given fqdn.
func lookupNameservers(fqdn string, resolvers []string) ([]string, error) {
	var authoritativeNss []string

	zone, err := findZoneByFQDN(fqdn, resolvers)
	if err != nil {
		return nil, fmt.Errorf("could not determine the zone: %w", err)
	}

	r, err := dnsQuery(zone, dnsmessage.TypeNS, resolvers, true)
	if err != nil {
		return nil, err
	}

	for _, rr := range r.Answers {
		if ns, ok := rr.Body.(*dnsmessage.NSResource); ok {
			authoritativeNss = append(authoritativeNss, strings.ToLower(ns.NS.String()))
		}
	}

	if len(authoritativeNss) > 0 {
		return authoritativeNss, nil
	}
	return nil, errors.New("could not determine authoritative nameservers")
}

// Update FQDN with CNAME if any
func updateDomainWithCName(r *dnsmessage.Message, fqdn string) string {
	for _, rr := range r.Answers {
		if cn, ok := rr.Body.(*dnsmessage.CNAMEResource); ok {
			if rr.Header.Name.String() == fqdn {
				return cn.CNAME.String()
			}
		}
	}
	return fqdn
}
