// Generates the synthetic MMDB fixtures used by the rsigma-runtime tests.
//
// Run `go run .` from this directory; it writes city-test.mmdb,
// city-test-updated.mmdb, city-test-v4.mmdb, asn-test.mmdb, and flat-test.mmdb
// into the parent directory. The data is synthetic: it uses only the RFC 5737 and RFC 3849
// documentation ranges, so IncludeReservedNetworks is required. Regenerate
// only when a test needs a different record shape or network, and re-run the
// golden tests with RSIGMA_UPDATE_GOLDEN=1 afterwards.
package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
)

func main() {
	if err := writeCity("city-test.mmdb", 1704067200, false); err != nil {
		fail(err)
	}
	if err := writeCity("city-test-updated.mmdb", 1735689600, true); err != nil {
		fail(err)
	}
	if err := writeASN("asn-test.mmdb"); err != nil {
		fail(err)
	}
	if err := writeFlat("flat-test.mmdb"); err != nil {
		fail(err)
	}
	if err := writeCityV4("city-test-v4.mmdb"); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func newWriter(databaseType string, buildEpoch int64) (*mmdbwriter.Tree, error) {
	return mmdbwriter.New(mmdbwriter.Options{
		DatabaseType:            databaseType,
		BuildEpoch:              buildEpoch,
		Description:             map[string]string{"en": "rsigma synthetic test database"},
		IncludeReservedNetworks: true,
		IPVersion:               6,
		Languages:               []string{"en"},
		RecordSize:              24,
	})
}

func cityRecord(
	countryISO, countryName string,
	subdivisionISO, subdivisionName string,
	cityName string,
	latitude, longitude float64,
	timeZone string,
) mmdbtype.Map {
	return mmdbtype.Map{
		"city": mmdbtype.Map{
			"names": mmdbtype.Map{"en": mmdbtype.String(cityName)},
		},
		"country": mmdbtype.Map{
			"iso_code": mmdbtype.String(countryISO),
			"names":    mmdbtype.Map{"en": mmdbtype.String(countryName)},
		},
		"location": mmdbtype.Map{
			"latitude":  mmdbtype.Float64(latitude),
			"longitude": mmdbtype.Float64(longitude),
			"time_zone": mmdbtype.String(timeZone),
		},
		"subdivisions": mmdbtype.Slice{
			mmdbtype.Map{
				"iso_code": mmdbtype.String(subdivisionISO),
				"names":    mmdbtype.Map{"en": mmdbtype.String(subdivisionName)},
			},
		},
	}
}

func insert(tree *mmdbwriter.Tree, cidr string, record mmdbtype.DataType) error {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	return tree.Insert(network, record)
}

func write(tree *mmdbwriter.Tree, name string) error {
	f, err := os.Create(filepath.Join("..", name))
	if err != nil {
		return err
	}
	if _, err := tree.WriteTo(f); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func writeCity(name string, buildEpoch int64, updated bool) error {
	tree, err := newWriter("GeoIP2-City", buildEpoch)
	if err != nil {
		return err
	}

	seattle := cityRecord("US", "United States", "WA", "Washington", "Seattle", 47.6062, -122.3321, "America/Los_Angeles")
	if updated {
		seattle = cityRecord("CA", "Canada", "BC", "British Columbia", "Vancouver", 49.2827, -123.1207, "America/Vancouver")
	}

	if err := insert(tree, "192.0.2.0/24", seattle); err != nil {
		return err
	}
	berlin := cityRecord("DE", "Germany", "BE", "Berlin", "Berlin", 52.52, 13.405, "Europe/Berlin")
	if err := insert(tree, "198.51.100.0/24", berlin); err != nil {
		return err
	}
	tokyo := cityRecord("JP", "Japan", "13", "Tokyo", "Tokyo", 35.6762, 139.6503, "Asia/Tokyo")
	if err := insert(tree, "2001:db8::/32", tokyo); err != nil {
		return err
	}

	if updated {
		london := cityRecord("GB", "United Kingdom", "ENG", "England", "London", 51.5074, -0.1278, "Europe/London")
		if err := insert(tree, "203.0.113.0/24", london); err != nil {
			return err
		}
	}

	return write(tree, name)
}

func writeCityV4(name string) error {
	tree, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType:            "GeoIP2-City",
		BuildEpoch:              1704067200,
		Description:             map[string]string{"en": "rsigma synthetic IPv4-only test database"},
		IncludeReservedNetworks: true,
		IPVersion:               4,
		Languages:               []string{"en"},
		RecordSize:              24,
	})
	if err != nil {
		return err
	}
	seattle := cityRecord("US", "United States", "WA", "Washington", "Seattle", 47.6062, -122.3321, "America/Los_Angeles")
	if err := insert(tree, "192.0.2.0/24", seattle); err != nil {
		return err
	}
	return write(tree, name)
}

func writeASN(name string) error {
	tree, err := newWriter("GeoLite2-ASN", 1704067200)
	if err != nil {
		return err
	}
	if err := insert(tree, "192.0.2.0/24", mmdbtype.Map{
		"autonomous_system_number":       mmdbtype.Uint32(64496),
		"autonomous_system_organization": mmdbtype.String("Example Transit"),
	}); err != nil {
		return err
	}
	if err := insert(tree, "198.51.100.0/24", mmdbtype.Map{
		"autonomous_system_number":       mmdbtype.Uint32(64511),
		"autonomous_system_organization": mmdbtype.String("Example Peering"),
	}); err != nil {
		return err
	}
	return write(tree, name)
}

func writeFlat(name string) error {
	tree, err := newWriter("IP2Proxy", 1704067200)
	if err != nil {
		return err
	}
	if err := insert(tree, "192.0.2.0/24", mmdbtype.Map{
		"is_proxy":     mmdbtype.Bool(true),
		"proxy_type":   mmdbtype.String("VPN"),
		"country_code": mmdbtype.String("US"),
		"usage_types":  mmdbtype.Slice{mmdbtype.String("DCH"), mmdbtype.String("VPN")},
	}); err != nil {
		return err
	}
	return write(tree, name)
}
