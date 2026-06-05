// Copyright (c) 2026 Alex Ackerman
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// filteredZoneListResponse is the response envelope for /api/blocked/list and
// /api/allowed/list. Records is non-empty when the queried domain exists.
type filteredZoneListResponse struct {
	Domain  string            `json:"domain"`
	Zones   []string          `json:"zones"`
	Records []json.RawMessage `json:"records"`
}

// exportFilteredZones fetches the plain-text export from the given path
// (e.g. /api/blocked/export or /api/allowed/export) and returns one domain
// per line. It bypasses do() because the export endpoint returns plain text,
// not JSON, but uses the same POST-form transport so the token stays out of
// the request URL.
func exportFilteredZones(ctx context.Context, c *Client, path string) ([]string, error) {
	form := url.Values{}
	form.Set("token", c.token)
	reqURL := fmt.Sprintf("%s%s", c.baseURL, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating request to %s: %w", path, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request to %s failed: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response from %s: %w", path, err)
	}

	// The export endpoint returns the domain list as plain text on success.
	// Anything other than 200 is an error page (auth failure, server error)
	// whose body must not be parsed as domains.
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status %d from %s", resp.StatusCode, path)
	}

	// An invalid/expired token still returns 200, but with a JSON error
	// envelope instead of plain text. Detect and surface it.
	if strings.HasPrefix(strings.TrimSpace(string(body)), "{") {
		var apiResp APIResponse
		if err := json.Unmarshal(body, &apiResp); err == nil && apiResp.Status != "" && apiResp.Status != "ok" {
			return nil, &APIError{Status: apiResp.Status, ErrorMessage: apiResp.ErrorMessage}
		}
	}

	text := strings.TrimSpace(string(body))
	if text == "" {
		return []string{}, nil
	}

	lines := strings.Split(text, "\n")
	domains := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			domains = append(domains, line)
		}
	}
	return domains, nil
}

// BlockedZoneAdd adds a domain to the blocked zone list. Idempotent.
func (c *Client) BlockedZoneAdd(ctx context.Context, domain string) error {
	params := url.Values{}
	params.Set("domain", domain)
	_, err := c.do(ctx, "/api/blocked/add", params)
	if err != nil {
		return fmt.Errorf("adding blocked zone %q: %w", domain, err)
	}
	return nil
}

// BlockedZoneDelete removes a domain from the blocked zone list. Idempotent.
func (c *Client) BlockedZoneDelete(ctx context.Context, domain string) error {
	params := url.Values{}
	params.Set("domain", domain)
	_, err := c.do(ctx, "/api/blocked/delete", params)
	if err != nil {
		return fmt.Errorf("deleting blocked zone %q: %w", domain, err)
	}
	return nil
}

// BlockedZoneExists returns true if the domain exists in the blocked zone list.
func (c *Client) BlockedZoneExists(ctx context.Context, domain string) (bool, error) {
	params := url.Values{}
	params.Set("domain", domain)
	apiResp, err := c.do(ctx, "/api/blocked/list", params)
	if err != nil {
		return false, fmt.Errorf("checking blocked zone %q: %w", domain, err)
	}

	var listResp filteredZoneListResponse
	if err := json.Unmarshal(apiResp.Response, &listResp); err != nil {
		return false, fmt.Errorf("decoding blocked zone list response: %w", err)
	}

	return len(listResp.Records) > 0, nil
}

// BlockedZoneList returns all domains in the blocked zone list.
func (c *Client) BlockedZoneList(ctx context.Context) ([]string, error) {
	domains, err := exportFilteredZones(ctx, c, "/api/blocked/export")
	if err != nil {
		return nil, fmt.Errorf("listing blocked zones: %w", err)
	}
	return domains, nil
}

// BlockedZoneImport adds multiple domains to the blocked zone list in one call.
func (c *Client) BlockedZoneImport(ctx context.Context, domains []string) error {
	params := url.Values{}
	params.Set("blockedZones", strings.Join(domains, ","))
	_, err := c.do(ctx, "/api/blocked/import", params)
	if err != nil {
		return fmt.Errorf("importing blocked zones: %w", err)
	}
	return nil
}

// BlockedZoneFlush removes all domains from the blocked zone list.
func (c *Client) BlockedZoneFlush(ctx context.Context) error {
	_, err := c.do(ctx, "/api/blocked/flush", nil)
	if err != nil {
		return fmt.Errorf("flushing blocked zones: %w", err)
	}
	return nil
}
