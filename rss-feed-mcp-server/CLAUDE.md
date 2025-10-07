# RSS Feed MCP Server - Claude Integration Guide

## Overview

This MCP server enables Claude to fetch and search cybersecurity RSS feeds from trusted sources including Krebs on Security, Bruce Schneier's cybersecurity posts, and Exploit-DB.

## Available Tools

### 1. get_krebs_feed(limit="10")
Fetches latest articles from Krebs on Security RSS feed.
- **limit**: Number of articles to retrieve (1-25, default: 10)

### 2. get_schneier_feed(limit="10") 
Gets cybersecurity articles from Bruce Schneier's blog.
- **limit**: Number of articles to retrieve (1-25, default: 10)

### 3. get_exploitdb_feed(limit="10")
Retrieves latest exploits and security advisories from Exploit-DB.
- **limit**: Number of articles to retrieve (1-25, default: 10)

### 4. get_all_feeds_summary(limit="5")
Provides a combined summary from all RSS feeds.
- **limit**: Number of articles per feed (1-10, default: 5)

### 5. search_feeds(query="", limit="10")
Searches for keywords across all RSS feeds.
- **query**: Search term or phrase (required)
- **limit**: Maximum results to return (1-10, default: 10)

## Implementation Details

### RSS Feed Sources
- **Krebs on Security**: General cybersecurity news and investigations
- **Bruce Schneier**: Expert analysis on cybersecurity topics  
- **Exploit-DB**: Latest exploits, vulnerabilities, and security tools

### Data Processing
- Real-time RSS feed parsing using feedparser library
- Date normalization for consistent formatting
- Content summarization (truncated at 300 characters)
- Error handling for malformed or inaccessible feeds

### Performance Considerations
- HTTP requests have 15-second timeout
- Entry limits prevent excessive data transfer
- Search function optimizes by prioritizing title matches
- No caching implemented (always fresh data)

### Error Handling
- Graceful degradation when feeds are unavailable
- Individual feed failures don't affect other feeds
- Detailed error messages for troubleshooting
- Logging to stderr for debugging

## Usage Patterns

### Stay Updated on Cybersecurity News
```
"What's new in cybersecurity today?"
```

### Research Specific Topics  
```
"Search for recent articles about zero-day vulnerabilities"
```

### Monitor Exploit Activity
```
"Show me the latest exploits from Exploit-DB"
```

### Get Focused Updates
```
"Get 5 latest articles from Krebs on Security"
```

## Best Practices

1. **Use appropriate limits** - Start with small numbers for exploration
2. **Be specific with search terms** - More targeted queries yield better results  
3. **Check multiple sources** - Use the summary tool for comprehensive coverage
4. **Verify information** - Always check source links for complete context

## Technical Notes

- RSS feeds are parsed in real-time (no caching)
- All dates converted to UTC format
- HTML content is preserved in summaries
- Links are always included for full article access
- Feed descriptions and metadata included when available

## Limitations

- Dependent on external RSS feed availability
- No historical data beyond what feeds provide
- Search is case-insensitive text matching only
- Rate limiting may apply from RSS sources
- Content is limited to what RSS feeds expose