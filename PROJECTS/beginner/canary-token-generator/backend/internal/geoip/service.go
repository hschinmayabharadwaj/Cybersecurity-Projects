// ©AngelaMos | 2026
// service.go

package geoip

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/oschwald/geoip2-golang/v2"
)

type Lookup struct {
	Country string
	Region  string
	City    string
	ASNOrg  string
	ASN     int
}

type Lookuper interface {
	Lookup(ip string) Lookup
}

type cityReader interface {
	City(netip.Addr) (*geoip2.City, error)
	Close() error
}

type Service struct {
	reader cityReader
}

func Open(path string) (*Service, error) {
	if path == "" {
		return nil, errors.New("geoip: path is empty")
	}
	r, err := geoip2.Open(path)
	if err != nil {
		return nil, fmt.Errorf("geoip open %q: %w", path, err)
	}
	return &Service{reader: r}, nil
}

func (s *Service) Lookup(ip string) Lookup {
	if s == nil || s.reader == nil || ip == "" {
		return Lookup{}
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return Lookup{}
	}
	rec, err := s.reader.City(addr)
	if err != nil || rec == nil || !rec.HasData() {
		return Lookup{}
	}
	return extractLookup(rec)
}

func (s *Service) Close() error {
	if s == nil || s.reader == nil {
		return nil
	}
	return s.reader.Close()
}

type nopService struct{}

func NopService() Lookuper {
	return nopService{}
}

func (nopService) Lookup(string) Lookup {
	return Lookup{}
}

func extractLookup(rec *geoip2.City) Lookup {
	if rec == nil {
		return Lookup{}
	}
	return Lookup{
		Country: rec.Country.ISOCode,
		Region:  firstSubdivisionName(rec.Subdivisions),
		City:    rec.City.Names.English,
	}
}

func firstSubdivisionName(subs []geoip2.CitySubdivision) string {
	for _, s := range subs {
		if s.Names.English != "" {
			return s.Names.English
		}
		if s.ISOCode != "" {
			return s.ISOCode
		}
	}
	return ""
}
