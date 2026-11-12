package jira

import "strings"

// CommentADF builds an Atlassian Document Format comment body from plain
// text: one paragraph per line, blank lines dropped. JIRA Cloud REST v3
// comments require ADF; attachments are not supported on comments, so
// everything the bridge posts is plain text.
func CommentADF(body string) map[string]any {
	var paragraphs []any
	for _, line := range strings.Split(body, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		paragraphs = append(paragraphs, map[string]any{
			"type": "paragraph",
			"content": []any{map[string]any{
				"type": "text",
				"text": line,
			}},
		})
	}
	return map[string]any{
		"type":    "doc",
		"version": 1,
		"content": paragraphs,
	}
}
