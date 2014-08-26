package domainstats

import (
	"log"
	"os"
	"path/filepath"
	"testing"

	"github.com/dead10ck/goinvestigate"
)

var (
	inv    *goinvestigate.Investigate
	config *Config
)

func init() {
	home := os.Getenv("HOME")
	var err error
	config, err = NewConfig(filepath.Join(home, ".domainstats/default.toml"))
	if err != nil {
		log.Fatal(err)
	}
}

func strSliceEq(a []string, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestExtractDomainCatInfo(t *testing.T) {
	dc := &goinvestigate.DomainCategorization{
		Status:             1,
		SecurityCategories: []string{"Malware", "Botnet", "Trojan"},
		ContentCategories:  []string{"8", "15", "23"},
	}
	ref := []string{"1", "Malware, Botnet, Trojan", "8, 15, 23"}
	test := config.extractDomainCatInfo(dc)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}

	// test with fields omitted
	config.Status = false
	ref = []string{"Malware, Botnet, Trojan", "8, 15, 23"}
	test = config.extractDomainCatInfo(dc)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}
	config.Status = true

	config.Categories.SecurityCategories = false
	ref = []string{"1", "8, 15, 23"}
	test = config.extractDomainCatInfo(dc)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}
	config.Categories.SecurityCategories = true

	// all off should return an empty slice
	config.Status = false
	config.Categories.SecurityCategories = false
	config.Categories.ContentCategories = false
	ref = []string{}
	test = config.extractDomainCatInfo(dc)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}
	config.Status = true
	config.Categories.SecurityCategories = true
	config.Categories.ContentCategories = true
}

func TestExtractRelatedDomainInfo(t *testing.T) {
	rd := []goinvestigate.RelatedDomain{
		goinvestigate.RelatedDomain{
			Domain: "www.example1.com",
			Score:  10,
		},
		goinvestigate.RelatedDomain{
			Domain: "info.example2.com.com",
			Score:  9,
		},
		goinvestigate.RelatedDomain{
			Domain: "support.example.com",
			Score:  3,
		},
	}

	ref := []string{"www.example1.com:10, info.example2.com.com:9, support.example.com:3"}
	test := config.extractRelatedDomainInfo(rd)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}

	// turn off scores
	config.Related.Score = false
	ref = []string{"www.example1.com, info.example2.com.com, support.example.com"}
	test = config.extractRelatedDomainInfo(rd)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}
	config.Related.Score = true

	// turn off domains
	config.Related.Domain = false
	ref = []string{"10, 9, 3"}
	test = config.extractRelatedDomainInfo(rd)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}
	config.Related.Domain = true

	// without either, should just return an empty slice
	config.Related.Domain = false
	config.Related.Score = false
	ref = []string{}
	test = config.extractRelatedDomainInfo(rd)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}
	config.Related.Domain = true
	config.Related.Score = true
}

func TestExtractCooccurrenceInfo(t *testing.T) {
	cl := []goinvestigate.Cooccurrence{
		goinvestigate.Cooccurrence{
			Domain: "download.example.com",
			Score:  0.9320288065469468,
		},
		goinvestigate.Cooccurrence{
			Domain: "query.example.com",
			Score:  0.06797119345305325,
		},
	}

	ref := []string{"download.example.com:0.9320288065469468, query.example.com:0.06797119345305325"}
	test := config.extractCooccurrenceInfo(cl)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}

	// turn off scores
	config.Cooccurrences.Score = false
	ref = []string{"download.example.com, query.example.com"}
	test = config.extractCooccurrenceInfo(cl)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}
	config.Cooccurrences.Score = true

	// turn off domains
	config.Cooccurrences.Domain = false
	ref = []string{"0.9320288065469468, 0.06797119345305325"}
	test = config.extractCooccurrenceInfo(cl)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}
	config.Cooccurrences.Domain = true

	// both false should return an empty slice
	config.Cooccurrences.Domain = false
	config.Cooccurrences.Score = false
	ref = []string{}
	test = config.extractCooccurrenceInfo(cl)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}
	config.Cooccurrences.Domain = true
	config.Cooccurrences.Score = true
}

func TestExtractSecurityFeaturesInfo(t *testing.T) {
	sec := &goinvestigate.SecurityFeatures{
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
		Geodiversity: []goinvestigate.GeoFeatures{
			goinvestigate.GeoFeatures{CountryCode: "UA", VisitRatio: 0.24074075},
			goinvestigate.GeoFeatures{CountryCode: "IN", VisitRatio: 0.018518519},
		},
		GeodiversityNormalized: []goinvestigate.GeoFeatures{
			goinvestigate.GeoFeatures{CountryCode: "AP", VisitRatio: 0.3761535390278368},
			goinvestigate.GeoFeatures{CountryCode: "US", VisitRatio: 0.0005015965168831449},
		},
		TLDGeodiversity: []goinvestigate.GeoFeatures{
			goinvestigate.GeoFeatures{CountryCode: "ID", VisitRatio: 0.3848226710420966},
			goinvestigate.GeoFeatures{CountryCode: "BY", VisitRatio: 0.1127399438411313},
		},
		Geoscore:   0,
		KSTest:     0,
		Attack:     "DDoS",
		ThreatType: "Malware",
	}
	ref := []string{"38.301771886101335", "0.4540313302593146",
		"2.5216406363433186", "-1.3135141095601992", "0.0262532",
		"-29.75810625887133", "-64.9070502788884", "-75.64720536038982",
		"25.335450495507196", "false",
		"UA:0.24074075, IN:0.018518519",
		"AP:0.3761535390278368, US:0.0005015965168831449",
		"ID:0.3848226710420966, BY:0.1127399438411313",
		"0", "0", "DDoS", "Malware",
	}
	test := config.extractSecurityFeaturesInfo(sec)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}

	// couple of sanity checks - turning off Perplexity and Entropy
	config.Security.Perplexity = false
	config.Security.Entropy = false
	ref = []string{"38.301771886101335", "-1.3135141095601992", "0.0262532",
		"-29.75810625887133", "-64.9070502788884", "-75.64720536038982",
		"25.335450495507196", "false",
		"UA:0.24074075, IN:0.018518519",
		"AP:0.3761535390278368, US:0.0005015965168831449",
		"ID:0.3848226710420966, BY:0.1127399438411313",
		"0", "0", "DDoS", "Malware",
	}
	test = config.extractSecurityFeaturesInfo(sec)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}
	config.Security.Perplexity = true
	config.Security.Entropy = true

	// turn off GeodiversityNormalized and TLDGeodiversity
	config.Security.GeodiversityNormalized = false
	config.Security.TLDGeodiversity = false
	ref = []string{"38.301771886101335", "0.4540313302593146",
		"2.5216406363433186", "-1.3135141095601992", "0.0262532",
		"-29.75810625887133", "-64.9070502788884", "-75.64720536038982",
		"25.335450495507196", "false",
		"UA:0.24074075, IN:0.018518519",
		"0", "0", "DDoS", "Malware",
	}
	test = config.extractSecurityFeaturesInfo(sec)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}
	config.Security.GeodiversityNormalized = true
	config.Security.TLDGeodiversity = true

	// turning off everyting should return an empty slice
	config.Security.DGAScore = false
	config.Security.Perplexity = false
	config.Security.Entropy = false
	config.Security.SecureRank2 = false
	config.Security.PageRank = false
	config.Security.ASNScore = false
	config.Security.PrefixScore = false
	config.Security.RIPScore = false
	config.Security.Fastflux = false
	config.Security.Popularity = false
	config.Security.Geodiversity = false
	config.Security.GeodiversityNormalized = false
	config.Security.TLDGeodiversity = false
	config.Security.Geoscore = false
	config.Security.KSTest = false
	config.Security.Attack = false
	config.Security.ThreatType = false
	ref = []string{}
	test = config.extractSecurityFeaturesInfo(sec)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}
	config.Security.DGAScore = true
	config.Security.Perplexity = true
	config.Security.Entropy = true
	config.Security.SecureRank2 = true
	config.Security.PageRank = true
	config.Security.ASNScore = true
	config.Security.PrefixScore = true
	config.Security.RIPScore = true
	config.Security.Fastflux = true
	config.Security.Popularity = true
	config.Security.Geodiversity = true
	config.Security.GeodiversityNormalized = true
	config.Security.TLDGeodiversity = true
	config.Security.Geoscore = true
	config.Security.KSTest = true
	config.Security.Attack = true
	config.Security.ThreatType = true
}

func TestExtractDomainTagInfo(t *testing.T) {
	dt := []goinvestigate.DomainTag{
		goinvestigate.DomainTag{
			Url:      "http://ancgrli.prophp.org/",
			Category: "Malware",
			Period: goinvestigate.PeriodType{
				Begin: "2014-04-07",
				End:   "Current",
			},
		},
		goinvestigate.DomainTag{
			Url:      "http://ancgrli.prophp.org/34/45791.html",
			Category: "Malware",
			Period: goinvestigate.PeriodType{
				Begin: "2014-03-04",
				End:   "2014-03-05",
			},
		},
	}

	ref := []string{
		"http://ancgrli.prophp.org/:Malware:2014-04-07:Current",
		"http://ancgrli.prophp.org/34/45791.html:Malware:2014-03-04:2014-03-05",
	}
	test := config.extractDomainTagInfo(dt)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}

	// turn off Category and Begin
	config.TaggingDates.Category = false
	config.TaggingDates.Begin = false
	ref = []string{
		"http://ancgrli.prophp.org/:Current",
		"http://ancgrli.prophp.org/34/45791.html:2014-03-05",
	}
	test = config.extractDomainTagInfo(dt)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}

	// turn off everything. Should return an empty slice
	config.TaggingDates.End = false
	config.TaggingDates.Url = false
	ref = []string{}
	test = config.extractDomainTagInfo(dt)
	if !strSliceEq(ref, test) {
		t.Fatalf("%v != %v", ref, test)
	}
	config.TaggingDates.Category = true
	config.TaggingDates.Begin = true
	config.TaggingDates.End = true
	config.TaggingDates.Url = true
}
