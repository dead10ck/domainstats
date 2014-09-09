package goinvestigate

import (
	"encoding/json"
	"errors"
	"fmt"
)

type DomainCategorization struct {
	Status             int
	ContentCategories  []string `json:"content_categories"`
	SecurityCategories []string `json:"security_categories"`
}

type Cooccurrence struct {
	Domain string
	Score  float64
}

type CooccurrenceList []Cooccurrence

func (r *CooccurrenceList) UnmarshalJSON(b []byte) error {
	var raw map[string]interface{}
	err := json.Unmarshal(b, &raw)
	if err != nil {
		return err
	}
	malfErr := errors.New(fmt.Sprintf("malformed object: %v", raw))
	pfs2, ok := raw["pfs2"]

	// empty list
	if !ok {
		*r = CooccurrenceList{}
		return nil
	}

	pfs2List, ok := pfs2.([]interface{})
	if !ok {
		return errors.New("Could not convert pfs2List to []interface{}")
	}

	*r = make([]Cooccurrence, len(pfs2List))
	for i, item := range pfs2List {
		// convert the entry into its double list
		itemList, ok := item.([]interface{})
		if !ok {
			r = nil
			return errors.New("Could not convert item to []interface{}")
		}

		// extract the domain and score
		d, ok := itemList[0].(string)
		if !ok {
			r = nil
			return malfErr
		}
		s, ok := itemList[1].(float64)
		if !ok {
			r = nil
			return malfErr
		}

		// put the domain into the list
		(*r)[i] = Cooccurrence{
			Domain: d,
			Score:  s,
		}
	}
	return nil
}

type RelatedDomain struct {
	Domain string
	Score  int
}

type RelatedDomainList []RelatedDomain

func (r *RelatedDomainList) UnmarshalJSON(b []byte) error {
	var raw map[string]interface{}
	err := json.Unmarshal(b, &raw)
	if err != nil {
		return err
	}
	malfErr := errors.New(fmt.Sprintf("malformed object: %v", raw))
	tb1, ok := raw["tb1"]

	// empty list
	if !ok {
		*r = RelatedDomainList{}
		return nil
	}

	tb1List, ok := tb1.([]interface{})
	if !ok {
		return errors.New("Could not convert tb1List to []interface{}")
	}

	*r = make([]RelatedDomain, len(tb1List))
	for i, item := range tb1List {
		// convert the entry into its double list
		itemList, ok := item.([]interface{})
		if !ok {
			r = nil
			return errors.New("Could not convert item to []interface{}")
		}

		// extract the domain and score
		d, ok := itemList[0].(string)
		if !ok {
			r = nil
			return malfErr
		}
		s, ok := itemList[1].(float64)
		if !ok {
			r = nil
			return malfErr
		}

		// put the domain into the list
		(*r)[i] = RelatedDomain{
			Domain: d,
			Score:  int(s),
		}
	}
	return nil
}

type GeoFeatures struct {
	CountryCode string
	VisitRatio  float64
}

func (gf *GeoFeatures) UnmarshalJSON(b []byte) error {
	finalGf := new(GeoFeatures)
	var raw interface{}
	err := json.Unmarshal(b, &raw)
	if err != nil {
		return err
	}
	malfErr := errors.New(fmt.Sprintf("malformed object: %v", raw))

	gfList, ok := raw.([]interface{})
	if !ok {
		return malfErr
	}

	if cc, ok := gfList[0].(string); !ok {
		return malfErr
	} else {
		finalGf.CountryCode = cc
	}

	if vr, ok := gfList[1].(float64); !ok {
		return malfErr
	} else {
		finalGf.VisitRatio = vr
	}

	*gf = *finalGf
	return nil
}

type SecurityFeatures struct {
	DGAScore               float64 `json:"dga_score"`
	Perplexity             float64
	Entropy                float64
	SecureRank2            float64 `json:"securerank2"`
	PageRank               float64 `json:"pagerank"`
	ASNScore               float64 `json:"asn_score"`
	PrefixScore            float64 `json:"prefix_score"`
	RIPScore               float64 `json:"rip_score"`
	Fastflux               bool
	Popularity             float64
	Geodiversity           []GeoFeatures `json:"geodiversity"`
	GeodiversityNormalized []GeoFeatures `json:"geodiversity_normalized"`
	TLDGeodiversity        []GeoFeatures `json:"tld_geodiversity"`
	Geoscore               float64
	KSTest                 float64 `json:"ks_test"`
	Attack                 string
	ThreatType             string `json:"threat_type"`
}

type PeriodType struct {
	Begin string
	End   string
}

type DomainTag struct {
	Url      string
	Category string
	Period   PeriodType
}

type ResourceRecord struct {
	Name  string
	TTL   int
	Class string
	Type  string
	RR    string
}

type ResourceRecordPeriod struct {
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
	RRs       []ResourceRecord
}

type Location struct {
	Lat float64
	Lon float64
}

type DomainResourceRecordFeatures struct {
	Age             int
	TTLsMin         int      `json:"ttls_min"`
	TTLsMax         int      `json:"ttls_max"`
	TTLsMean        float64  `json:"ttls_mean"`
	TTLsMedian      float64  `json:"ttls_median"`
	TTLsStdDev      float64  `json:"ttls_stddev"`
	CountryCodes    []string `json:"country_codes"`
	ASNs            []int
	Prefixes        []string
	RIPSCount       int     `json:"rips"`
	RIPSDiversity   float64 `json:"div_rips"`
	Locations       []Location
	GeoDistanceSum  float64 `json:"geo_distance_sum"`
	GeoDistanceMean float64 `json:"geo_distance_mean"`
	NonRoutable     bool    `json:"non_routable"`
	MailExchanger   bool    `json:"mail_exchanger"`
	CName           bool
	FFCandidate     bool    `json:"ff_candidate"`
	RIPSStability   float64 `json:"rips_stability"`
	BaseDomain      string  `json:"base_domain"`
	IsSubdomain     bool    `json:"is_subdomain"`
}

type DomainRRHistory struct {
	RRPeriods  []ResourceRecordPeriod       `json:"rrs_tf"`
	RRFeatures DomainResourceRecordFeatures `json:"features"`
}

type IPResourceRecordFeatures struct {
	RRCount   int     `json:"rr_count"`
	LD2Count  int     `json:"ld2_count"`
	LD3Count  int     `json:"ld3_count"`
	LD21Count int     `json:"ld2_1_count"`
	LD22Count int     `json:"ld2_2_count"`
	DivLD2    float64 `json:"div_ld2"`
	DivLD3    float64 `json:"div_ld3"`
	DivLD21   float64 `json:"div_ld2_1"`
	DivLD22   float64 `json:"div_ld2_2"`
}

type IPRRHistory struct {
	RRs        []ResourceRecord
	RRFeatures IPResourceRecordFeatures `json:"features"`
}

type MaliciousDomain struct {
	Domain string `json:"name"`
	Id     int
}
