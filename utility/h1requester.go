// hackerone.go
package hackeronereq

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
)

type CveData struct {
	Data struct {
		Ranked_cve_entries struct {
			__Typename string `json:"__typename"`
			Edges      []struct {
				__Typename string `json:"__typename"`
				Node       struct {
					__Typename              string   `json:"__typename"`
					Cve_description         string   `json:"cve_description"`
					Cve_id                  string   `json:"cve_id"`
					Epss                    float64  `json:"epss"`
					Id                      string   `json:"id"`
					Products                []string `json:"products"`
					Rank                    int      `json:"rank"`
					Reports_submitted_count int      `json:"reports_submitted_count"`
					Vendors                 []string `json:"vendors"`
				} `json:"node"`
			} `json:"edges"`
			PageInfo struct {
				__Typename      string `json:"__typename"`
				EndCursor       string `json:"endCursor"`
				HasNextPage     bool   `json:"hasNextPage"`
				HasPreviousPage bool   `json:"hasPreviousPage"`
				StartCursor     string `json:"startCursor"`
			} `json:"pageInfo"`
			Total_count int `json:"total_count"`
		} `json:"ranked_cve_entries"`
	} `json:"data"`
}

// GetData fetches data from the HackerOne API based on the provided offset.
func GetData(offset int) (*CveData, error) {
	url := "https://hackerone.com/graphql"
	payload := []byte(`{"operationName":"CveDataQuery","variables":{"first":50,"offset":` + strconv.Itoa(offset) + `,"search":"","orderBy":{"key":"reports_submitted_count","direction":"desc"},"product_area":"hacktivity","product_feature":"cve_discovery"},"query":"query CveDataQuery($first: Int, $after: String, $last: Int, $before: String, $search: String, $offset: Int, $orderBy: AnalyticsOrderByInputType) {\n  ranked_cve_entries(\n    first: $first\n    after: $after\n    last: $last\n    before: $before\n    search: $search\n    offset: $offset\n    order_by: $orderBy\n  ) {\n    total_count\n    pageInfo {\n      hasNextPage\n      endCursor\n      hasPreviousPage\n      startCursor\n      __typename\n    }\n    edges {\n      node {\n        id\n        cve_id\n        cve_description\n        rank\n        reports_submitted_count\n        products\n        vendors\n        epss\n        __typename\n      }\n      __typename\n    }\n    __typename\n  }\n}\n"}`)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}

	req.Header.Set("Host", "hackerone.com")
	req.Header.Set("Content-Length", "788")
	req.Header.Set("Sec-Ch-Ua", `"Not.A/Brand";v="8", "Chromium";v="114", "Microsoft Edge";v="114"`)
	req.Header.Set("Sec-Ch-Ua-Mobile", "?0")
	req.Header.Set("X-Datadog-Origin", "rum")
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36 Edg/114.0.1823.67")
	req.Header.Set("X-Datadog-Sampling-Priority", "1")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Product-Feature", "cve_discovery")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("X-Product-Area", "hacktivity")
	req.Header.Set("X-Datadog-Parent-Id", "6468917377491914687")
	req.Header.Set("X-Datadog-Trace-Id", "2645750746471839886")
	req.Header.Set("Sec-Ch-Ua-Platform", `"Linux"`)
	req.Header.Set("Origin", "https://hackerone.com")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Referer", "https://hackerone.com/hacktivity/cve_discovery")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Accept-Language", "en-GB,en;q=0.9,en-US;q=0.8")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()

	var reader io.ReadCloser

	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		reader, err = gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("error creating gzip reader: %v", err)
		}
		defer reader.Close()
	default:
		reader = resp.Body
	}

	body, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	var data CveData
	err = json.Unmarshal(body, &data)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling JSON: %v", err)
	}

	return &data, nil
}
