package goinvestigate

import (
	"flag"
	"fmt"
	"log"
	"os"
	"testing"
)

var (
	key string
	inv *Investigate
)

func init() {
	verbose := flag.Bool("sgverbose", false, "Set SGraph output to verbose.")
	flag.Parse()
	key := os.Getenv("INVESTIGATE_KEY")
	if key == "" {
		log.Fatal("INVESTIGATE_KEY environment variable not set")
	}
	inv = New(key)
	inv.SetVerbose(*verbose)
}

func TestIPRRHistory(t *testing.T) {
	out, err := inv.IpRRHistory("208.64.121.161", "A")
	if err != nil {
		t.Fatal(err)
	}

	if len(out.RRs) <= 0 {
		t.Fatal("RRs should not be empty")
	}

	if out.RRFeatures == (IPResourceRecordFeatures{}) {
		t.Fatal("empty features")
	}
}

func TestDomainRRHistory(t *testing.T) {
	out, err := inv.DomainRRHistory("bibikun.ru", "A")
	if err != nil {
		t.Fatal(err)
	}

	if len(out.RRPeriods) <= 0 {
		t.Fatal("RRPeriods should not be empty")
	}

	// can't compare hard-coded expected values, since the scores
	// change over time
	//if out.RRFeatures == (DomainResourceRecordFeatures{}) {
	//t.Fatal("empty features")
	//}
}

func TestCategorization(t *testing.T) {
	out, err := inv.Categorization("www.amazon.com", false)
	if err != nil {
		t.Fatal(err)
	}

	ref := &DomainCategorization{
		Status:             1,
		ContentCategories:  []string{"8"},
		SecurityCategories: []string{},
	}

	if out.Status != ref.Status ||
		out.ContentCategories[0] != ref.ContentCategories[0] ||
		len(out.SecurityCategories) != 0 {
		t.Fatalf("%v should be %v", out, ref)
	}

	out, err = inv.Categorization("www.amazon.com", true)
	ref = &DomainCategorization{
		Status:             1,
		ContentCategories:  []string{"Ecommerce/Shopping"},
		SecurityCategories: []string{},
	}

	if out.Status != ref.Status ||
		out.ContentCategories[0] != ref.ContentCategories[0] ||
		len(out.SecurityCategories) != 0 {
		t.Fatalf("%v should be %v", out, ref)
	}
}

func TestCategorizations(t *testing.T) {
	domains := []string{"www.amazon.com", "www.opendns.com", "bibikun.ru"}
	out, err := inv.Categorizations(domains, true)
	if err != nil {
		t.Fatal(err)
	}

	ref := map[string]DomainCategorization{
		"www.amazon.com": DomainCategorization{
			Status:             1,
			ContentCategories:  []string{"Ecommerce/Shopping"},
			SecurityCategories: []string{},
		},
		"www.opendns.com": DomainCategorization{
			Status:             1,
			ContentCategories:  []string{},
			SecurityCategories: []string{},
		},
		"bibikun.ru": DomainCategorization{
			Status:             -1,
			ContentCategories:  []string{},
			SecurityCategories: []string{"Malware"},
		},
	}

	if out["www.amazon.com"].Status != ref["www.amazon.com"].Status ||
		out["www.amazon.com"].ContentCategories[0] != ref["www.amazon.com"].ContentCategories[0] ||
		len(out["www.amazon.com"].SecurityCategories) != 0 {
		t.Fatalf("%v should be %v", out, ref)
	}

	if out["www.opendns.com"].Status != ref["www.opendns.com"].Status ||
		len(out["www.opendns.com"].ContentCategories) != 0 ||
		len(out["www.opendns.com"].SecurityCategories) != 0 {
		t.Fatalf("%v should be %v", out, ref)
	}

	if out["bibikun.ru"].Status != ref["bibikun.ru"].Status ||
		out["bibikun.ru"].SecurityCategories[0] != ref["bibikun.ru"].SecurityCategories[0] ||
		len(out["bibikun.ru"].ContentCategories) != 0 {
		t.Fatalf("%v should be %v", out, ref)
	}
}

func TestRelatedDomains(t *testing.T) {
	out, err := inv.RelatedDomains("www.test.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(out) <= 0 {
		t.Fatal(fmt.Sprintf("%v should not be empty", out))
	}
}

func TestCooccurrences(t *testing.T) {
	out, err := inv.Cooccurrences("www.test.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(out) <= 0 {
		t.Fatal(fmt.Sprintf("%v should not be empty", out))
	}
}

func TestSecurity(t *testing.T) {
	out, err := inv.Security("www.test.com")
	if err != nil {
		t.Fatal(err)
	}
	if out == nil {
		t.Fatalf("response object was nil")
	}
}

func TestDomainTags(t *testing.T) {
	out, err := inv.DomainTags("bibikun.ru")
	if err != nil {
		t.Fatal(err)
	}
	if len(out) <= 0 {
		t.Fatal(fmt.Sprintf("%v should not be empty"), out)
	}
}

func TestLatestDomains(t *testing.T) {
	outSlice, err := inv.LatestDomains("46.161.41.43")

	if err != nil {
		t.Fatal(err)
	}

	if len(outSlice) <= 0 {
		t.Fatal("empty list")
	}
}

func TestErrorResponse(t *testing.T) {
	badInv := New("bad_key")
	badInv.SetVerbose(true)
	_, err := badInv.Categorization("www.google.com", true)

	// should return an error
	if err == nil {
		t.Fatal("should return an authentication error")
	}
}
