package goinvestigate

import (
	"encoding/json"
	"runtime"
	"testing"
)

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}

func TestUnmarshalDomainCategorization(t *testing.T) {
	t.Parallel()
	data := []byte(
		`{
	"status": 1,
	"security_categories": [
		"Malware"
	],
	"content_categories": [
	  "8"
	]
}`)

	refDc := DomainCategorization{
		Status:             1,
		SecurityCategories: []string{"Malware"},
		ContentCategories:  []string{"8"},
	}

	var testDc DomainCategorization
	err := json.Unmarshal(data, &testDc)

	if err != nil {
		t.Fatal(err)
	}

	if refDc.Status != testDc.Status ||
		!strSliceEq(refDc.ContentCategories, testDc.ContentCategories) ||
		!strSliceEq(refDc.SecurityCategories, testDc.SecurityCategories) {
		t.Fatalf("%v != %v", refDc, testDc)
	}
}

func TestUnmarshallCooccurrenceList(t *testing.T) {
	t.Parallel()
	data := []byte(
		`{
	"pfs2": [
    [
      "download.example.com",
      0.9320288065469468
    ],
    [
      "query.example.com",
      0.06797119345305325
    ]
  ],
  "found": true
  }`,
	)

	refCl := CooccurrenceList{
		Cooccurrence{
			Domain: "download.example.com",
			Score:  0.9320288065469468,
		},
		Cooccurrence{
			Domain: "query.example.com",
			Score:  0.06797119345305325,
		},
	}

	var testCl CooccurrenceList
	err := json.Unmarshal(data, &testCl)

	if err != nil {
		t.Fatal(err)
	}

	if len(testCl) != len(refCl) {
		t.Fatalf("%v != %v", testCl, refCl)
	}

	for i := range testCl {
		if testCl[i] != refCl[i] {
			t.Fatalf("%v != %v", testCl, refCl)
		}
	}
}

func TestUnmarshallRelatedDomainList(t *testing.T) {
	t.Parallel()
	data := []byte(
		`{
  "tb1": [
    [
      "www.example1.com",
      10
    ],
    [
      "info.example2.com.com",
      9
    ],
    [
      "support.example.com",
      3
    ]
  ],
  "found": true
}`,
	)

	refRdl := RelatedDomainList{
		RelatedDomain{
			Domain: "www.example1.com",
			Score:  10,
		},
		RelatedDomain{
			Domain: "info.example2.com.com",
			Score:  9,
		},
		RelatedDomain{
			Domain: "support.example.com",
			Score:  3,
		},
	}

	var testRdl RelatedDomainList
	err := json.Unmarshal(data, &testRdl)

	if err != nil {
		t.Fatal(err)
	}

	if len(testRdl) != len(refRdl) {
		t.Fatalf("%v != %v", testRdl, refRdl)
	}

	for i := range testRdl {
		if testRdl[i] != refRdl[i] {
			t.Fatalf("%v != %v", testRdl, refRdl)
		}
	}
}

func TestUnmarshalSecurityFeatures(t *testing.T) {
	t.Parallel()
	data := []byte(
		`{
  "dga_score": 38.301771886101335,
  "perplexity": 0.4540313302593146,
  "entropy": 2.5216406363433186,
  "securerank2": -1.3135141095601992,
  "pagerank": 0.0262532,
  "asn_score": -29.75810625887133,
  "prefix_score": -64.9070502788884,
  "rip_score": -75.64720536038982,
  "popularity": 25.335450495507196,
  "fastflux": false,
  "geodiversity": [
    [
      "UA",
      0.24074075
    ],
    [
      "IN",
      0.018518519
    ]
  ],
  "geodiversity_normalized": [
    [
      "AP",
      0.3761535390278368
    ],
    [
      "US",
      0.0005015965168831449
    ]
  ],
  "tld_geodiversity": [
	["ID",0.3848226710420966],
	["BY",0.1127399438411313]
  ],
  "geoscore": 0,
  "ks_test": 0,
  "found": true
}`,
	)

	refSecF := SecurityFeatures{
		DGAScore:    38.301771886101335,
		Perplexity:  0.4540313302593146,
		Entropy:     2.5216406363433186,
		SecureRank2: -1.3135141095601992,
		PageRank:    0.0262532,
		ASNScore:    -29.75810625887133,
		PrefixScore: -64.9070502788884,
		RIPScore:    -75.64720536038982,
		Popularity:  25.335450495507196,
		Fastflux:    false,
		Geodiversity: []GeoFeatures{
			GeoFeatures{CountryCode: "UA", VisitRatio: 0.24074075},
			GeoFeatures{CountryCode: "IN", VisitRatio: 0.018518519},
		},
		GeodiversityNormalized: []GeoFeatures{
			GeoFeatures{CountryCode: "AP", VisitRatio: 0.3761535390278368},
			GeoFeatures{CountryCode: "US", VisitRatio: 0.0005015965168831449},
		},
		TLDGeodiversity: []GeoFeatures{
			GeoFeatures{CountryCode: "ID", VisitRatio: 0.3848226710420966},
			GeoFeatures{CountryCode: "BY", VisitRatio: 0.1127399438411313},
		},
		Geoscore: 0,
		KSTest:   0,
	}

	var testSecF SecurityFeatures
	err := json.Unmarshal(data, &testSecF)

	if err != nil {
		t.Fatal(err)
	}

	if testSecF.DGAScore != refSecF.DGAScore ||
		testSecF.Perplexity != refSecF.Perplexity ||
		testSecF.Entropy != refSecF.Entropy ||
		testSecF.SecureRank2 != refSecF.SecureRank2 ||
		testSecF.PageRank != refSecF.PageRank ||
		testSecF.ASNScore != refSecF.ASNScore ||
		testSecF.PrefixScore != refSecF.PrefixScore ||
		testSecF.RIPScore != refSecF.RIPScore ||
		testSecF.Fastflux != refSecF.Fastflux ||
		testSecF.Popularity != refSecF.Popularity ||
		!geoFeaturesEq(testSecF.Geodiversity, refSecF.Geodiversity) ||
		!geoFeaturesEq(testSecF.GeodiversityNormalized, refSecF.GeodiversityNormalized) ||
		!geoFeaturesEq(testSecF.TLDGeodiversity, refSecF.TLDGeodiversity) ||
		testSecF.Geoscore != refSecF.Geoscore ||
		testSecF.KSTest != refSecF.KSTest ||
		testSecF.Attack != refSecF.Attack ||
		testSecF.ThreatType != refSecF.ThreatType {
		t.Fatalf("%v != %v", refSecF, testSecF)
	}
}

func TestUnmarshalDomainTags(t *testing.T) {
	t.Parallel()
	data := []byte(
		`[
  {
    "period": {
      "begin": "2014-04-07",
      "end": "Current"
    },
    "category": "Malware",
    "url": "http://ancgrli.prophp.org/"
  },
  {
    "period": {
      "begin": "2014-03-04",
      "end": "2014-03-05"
    },
    "category": "Malware",
    "url": "http://ancgrli.prophp.org/34/45791.html"
  }
]`,
	)

	refDt := []DomainTag{
		DomainTag{
			Url:      "http://ancgrli.prophp.org/",
			Category: "Malware",
			Period: PeriodType{
				Begin: "2014-04-07",
				End:   "Current",
			},
		},
		DomainTag{
			Url:      "http://ancgrli.prophp.org/34/45791.html",
			Category: "Malware",
			Period: PeriodType{
				Begin: "2014-03-04",
				End:   "2014-03-05",
			},
		},
	}

	var testDt []DomainTag
	err := json.Unmarshal(data, &testDt)

	if err != nil {
		t.Fatal(err)
	}

	if len(refDt) != len(testDt) {
		t.Fatalf("%v != %v", refDt, testDt)
	}

	for i := range refDt {
		if refDt[i] != testDt[i] {
			t.Fatalf("%v != %v", refDt, testDt)
		}
	}
}

func TestUnmarshalDomainRRHistory(t *testing.T) {
	t.Parallel()
	data := []byte(
		`{
  "rrs_tf": [
    {
      "first_seen": "2013-07-31",
      "last_seen": "2013-10-17",
      "rrs": [
        {
          "name": "example.com.",
          "ttl": 86400,
          "class": "IN",
          "type": "A",
          "rr": "93.184.216.119"
        }
      ]
    }
  ],
  "features": {
    "age": 91,
    "ttls_min": 86400,
    "ttls_max": 172800,
    "ttls_mean": 129600,
    "ttls_median": 129600,
    "ttls_stddev": 43200,
    "country_codes": [
      "US"
    ],
    "country_count": 1,
    "asns": [
      15133,
      40528
    ],
    "asns_count": 2,
    "prefixes": [
      "93.184.208.0",
      "192.0.43.0"
    ],
    "prefixes_count": 2,
    "rips": 2,
    "div_rips": 1,
    "locations": [
      {
        "lat": 38,
        "lon": -97
      },
      {
        "lat": 33.78659999999999,
        "lon": -118.2987
      }
    ],
    "locations_count": 2,
    "geo_distance_sum": 1970.1616237100388,
    "geo_distance_mean": 985.0808118550194,
    "non_routable": false,
    "mail_exchanger": false,
    "cname": false,
    "ff_candidate": false,
    "rips_stability": 0.5
  }
}`,
	)

	refDRR := DomainRRHistory{
		RRPeriods: []ResourceRecordPeriod{
			ResourceRecordPeriod{
				FirstSeen: "2013-07-31",
				LastSeen:  "2013-10-17",
				RRs: []ResourceRecord{
					ResourceRecord{
						Name:  "example.com.",
						TTL:   86400,
						Class: "IN",
						Type:  "A",
						RR:    "93.184.216.119",
					},
				},
			},
		},
		RRFeatures: DomainResourceRecordFeatures{
			Age:           91,
			TTLsMin:       86400,
			TTLsMax:       172800,
			TTLsMean:      129600,
			TTLsMedian:    129600,
			TTLsStdDev:    43200,
			CountryCodes:  []string{"US"},
			ASNs:          []int{15133, 40528},
			Prefixes:      []string{"93.184.208.0", "192.0.43.0"},
			RIPSCount:     2,
			RIPSDiversity: 1,
			Locations: []Location{
				Location{
					Lat: 38.0,
					Lon: -97.0,
				},
				Location{
					Lat: 33.78659999999999,
					Lon: -118.2987,
				},
			},
			GeoDistanceSum:  1970.1616237100388,
			GeoDistanceMean: 985.0808118550194,
			NonRoutable:     false,
			MailExchanger:   false,
			CName:           false,
			FFCandidate:     false,
			RIPSStability:   0.5,
		},
	}

	var testDRR DomainRRHistory
	err := json.Unmarshal(data, &testDRR)

	if err != nil {
		t.Fatal(err)
	}

	if testDRR.RRPeriods[0].FirstSeen != refDRR.RRPeriods[0].FirstSeen ||
		testDRR.RRPeriods[0].LastSeen != refDRR.RRPeriods[0].LastSeen ||
		testDRR.RRPeriods[0].RRs[0] != refDRR.RRPeriods[0].RRs[0] ||
		testDRR.RRFeatures.Age != refDRR.RRFeatures.Age ||
		testDRR.RRFeatures.TTLsMin != refDRR.RRFeatures.TTLsMin ||
		testDRR.RRFeatures.TTLsMax != refDRR.RRFeatures.TTLsMax ||
		testDRR.RRFeatures.TTLsMedian != refDRR.RRFeatures.TTLsMedian ||
		testDRR.RRFeatures.TTLsStdDev != refDRR.RRFeatures.TTLsStdDev ||
		!strSliceEq(testDRR.RRFeatures.CountryCodes, refDRR.RRFeatures.CountryCodes) ||
		!intSliceEq(testDRR.RRFeatures.ASNs, refDRR.RRFeatures.ASNs) ||
		!strSliceEq(testDRR.RRFeatures.Prefixes, refDRR.RRFeatures.Prefixes) ||
		testDRR.RRFeatures.RIPSCount != refDRR.RRFeatures.RIPSCount ||
		testDRR.RRFeatures.RIPSDiversity != refDRR.RRFeatures.RIPSDiversity ||
		!locationSliceEq(testDRR.RRFeatures.Locations, refDRR.RRFeatures.Locations) ||
		testDRR.RRFeatures.GeoDistanceSum != refDRR.RRFeatures.GeoDistanceSum ||
		testDRR.RRFeatures.NonRoutable != refDRR.RRFeatures.NonRoutable ||
		testDRR.RRFeatures.MailExchanger != refDRR.RRFeatures.MailExchanger ||
		testDRR.RRFeatures.CName != refDRR.RRFeatures.CName ||
		testDRR.RRFeatures.FFCandidate != refDRR.RRFeatures.FFCandidate ||
		testDRR.RRFeatures.RIPSStability != refDRR.RRFeatures.RIPSStability {
		t.Fatalf("%v != %v", refDRR, testDRR)
	}
}

func TestUnmarshalIPRRHistory(t *testing.T) {
	t.Parallel()
	data := []byte(
		`{
  "rrs": [
    {
      "rr": "www.example.com.",
      "ttl": 86400,
      "class": "IN",
      "type": "A",
      "name": "93.184.216.119"
    },
    {
      "rr": "www.example.net.",
      "ttl": 86400,
      "class": "IN",
      "type": "A",
      "name": "93.184.216.119"
    }
  ],
  "features": {
    "rr_count": 19,
    "ld2_count": 10,
    "ld3_count": 14,
    "ld2_1_count": 7,
    "ld2_2_count": 11,
    "div_ld2": 0.5263157894736842,
    "div_ld3": 0.7368421052631579,
    "div_ld2_1": 0.3684210526315789,
    "div_ld2_2": 0.5789473684210527
  }
}`,
	)

	ref := IPRRHistory{
		RRs: []ResourceRecord{
			ResourceRecord{
				RR:    "www.example.com.",
				TTL:   86400,
				Class: "IN",
				Type:  "A",
				Name:  "93.184.216.119",
			},
			ResourceRecord{
				RR:    "www.example.net.",
				TTL:   86400,
				Class: "IN",
				Type:  "A",
				Name:  "93.184.216.119",
			},
		},
		RRFeatures: IPResourceRecordFeatures{
			RRCount:   19,
			LD2Count:  10,
			LD3Count:  14,
			LD21Count: 7,
			LD22Count: 11,
			DivLD2:    0.5263157894736842,
			DivLD3:    0.7368421052631579,
			DivLD21:   0.3684210526315789,
			DivLD22:   0.5789473684210527,
		},
	}

	var test IPRRHistory
	err := json.Unmarshal(data, &test)
	if err != nil {
		t.Fatal(err)
	}

	if ref.RRs[0] != test.RRs[0] ||
		ref.RRs[1] != test.RRs[1] ||
		ref.RRFeatures != test.RRFeatures {
		t.Fatalf("%v != %v", ref, test)
	}
}

func TestUnmarshalMaliciousDomain(t *testing.T) {
	t.Parallel()
	data := []byte(
		`[
  {
    "id": 22842894,
    "name": "www.cxhyly.com"
  },
  {
    "id": 22958747,
    "name": "cxhyly.com"
  }
]`,
	)

	ref := []MaliciousDomain{
		MaliciousDomain{
			Domain: "www.cxhyly.com",
			Id:     22842894,
		},
		MaliciousDomain{
			Domain: "cxhyly.com",
			Id:     22958747,
		},
	}

	var test []MaliciousDomain
	err := json.Unmarshal(data, &test)
	if err != nil {
		t.Fatal(err)
	}

	if len(ref) != len(test) {
		t.Fatalf("%v != %v", ref, test)
	}

	for i := range ref {
		if ref[i] != test[i] {
			t.Fatalf("%v != %v", ref, test)
		}
	}
}

func locationSliceEq(a []Location, b []Location) bool {
	if len(a) != len(b) {
		return false
	}

	for i := 0; i < len(a); i++ {
		if a[i].Lat != b[i].Lat {
			return false
		}
		if a[i].Lon != b[i].Lon {
			return false
		}
	}

	return true
}

func intSliceEq(a []int, b []int) bool {
	if len(a) != len(b) {
		return false
	}

	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}

func geoFeaturesEq(a []GeoFeatures, b []GeoFeatures) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i].CountryCode != b[i].CountryCode {
			return false
		} else if a[i].VisitRatio != b[i].VisitRatio {
			return false
		}
	}

	return true
}

func strSliceEq(a []string, b []string) bool {
	if len(a) != len(b) {
		return false
	}

	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}
