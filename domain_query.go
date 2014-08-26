package domainstats

import "github.com/dead10ck/goinvestigate"

type DomainQueryType interface {
	Query() DomainQueryResponse
}

type DomainQuery struct {
	inv    *goinvestigate.Investigate
	domain string
}

type DomainQueryMessage struct {
	Q        DomainQueryType
	RespChan chan DomainQueryResponse
}

type DomainQueryResponse struct {
	Resp interface{}
	Err  error
}

type CategorizationQuery struct {
	DomainQuery
	labels bool
}

func (q *CategorizationQuery) Query() DomainQueryResponse {
	resp, err := q.inv.Categorization(q.domain, q.labels)
	return DomainQueryResponse{Resp: resp, Err: err}
}

type RelatedQuery struct {
	DomainQuery
}

func (q *RelatedQuery) Query() DomainQueryResponse {
	resp, err := q.inv.RelatedDomains(q.domain)
	return DomainQueryResponse{Resp: resp, Err: err}
}

type CooccurrencesQuery struct {
	DomainQuery
}

func (q *CooccurrencesQuery) Query() DomainQueryResponse {
	resp, err := q.inv.RelatedDomains(q.domain)
	return DomainQueryResponse{Resp: resp, Err: err}
}

type SecurityQuery struct {
	DomainQuery
}

func (q *SecurityQuery) Query() DomainQueryResponse {
	resp, err := q.inv.Security(q.domain)
	return DomainQueryResponse{Resp: resp, Err: err}
}

type DomainTagsQuery struct {
	DomainQuery
}

func (q *DomainTagsQuery) Query() DomainQueryResponse {
	resp, err := q.inv.DomainTags(q.domain)
	return DomainQueryResponse{Resp: resp, Err: err}
}
