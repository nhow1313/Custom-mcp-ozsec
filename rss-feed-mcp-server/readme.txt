# RSS Feed MCP Server

A Model Context Protocol (MCP) server that queries cybersecurity RSS feeds for the latest articles and security information.

## Purpose

This MCP server provides a secure interface for AI assistants to fetch and search the latest cybersecurity news and exploit information from trusted RSS feeds.

## Features

### Current Implementation

- **`get_krebs_feed`** - Fetch latest articles from Krebs on Security
- **`get_schneier_feed`** - Get cybersecurity articles from Bruce Schneier's blog  
- **`get_exploitdb_feed`** - Retrieve latest exploits and advisories from Exploit-DB
- **`get_all_feeds_summary`** - Get a combined summary from all feeds
- **`search_feeds`** - Search for specific keywords across all RSS feeds

### Supported RSS Feeds

- **Krebs on Security** - https://krebsonsecurity.com/feed
- **Bruce Schneier (Cybersecurity)** - https://schneier.com/tag/cybersecurity/feed
- **Exploit-DB** - https://www.exploit-db.com/rss.xml

## Prerequisites

- Docker Desktop with MCP Toolkit enabled
- Docker MCP CLI plugin (`docker mcp` command)
- Internet connection to fetch RSS feeds

## Installation

See the step-by-step instructions provided with the files.

## Usage Examples

In Claude Desktop, you can ask:

- "What are the latest articles from Krebs on Security?"
- "Show me the newest cybersecurity posts from Bruce Schneier"
- "Get the latest exploits from Exploit-DB"
- "Give me a summary of all cybersecurity feeds"
- "Search for articles about 'ransomware' in all feeds"
- "Find recent posts mentioning 'vulnerability'"

## Architecture

```
Claude Desktop → MCP Gateway → RSS Feed MCP Server → RSS Feeds
                                                   ↓
                                    [Krebs, Schneier, Exploit-DB]
```

## Development

### Local Testing

```bash
# Run directly
python rss_feed_server.py

# Test MCP protocol
echo '{"jsonrpc":"2.0","method":"tools/list","id":1}' | python rss_feed_server.py
```

### Adding New RSS Feeds

1. Add the feed URL to the `RSS_FEEDS` dictionary in `rss_feed_server.py`
2. Optionally create a dedicated tool function for the new feed
3. Update the catalog entry with any new tool names
4. Rebuild the Docker image

## Troubleshooting

### Tools Not Appearing

- Verify Docker image built successfully
- Check catalog and registry files
- Ensure Claude Desktop config includes custom catalog
- Restart Claude Desktop

### Feed Fetch Errors

- Check internet connectivity
- Verify RSS feed URLs are accessible
- Some feeds may have rate limiting or temporary outages
- Check server logs with `docker logs [container_name]`

### Performance Notes

- RSS feeds are fetched in real-time (not cached)
- Each query makes HTTP requests to external services
- Limit parameter caps at 25 entries per feed for performance
- Search function may be slower as it fetches more entries

## Security Considerations

- No authentication required (public RSS feeds)
- All external requests use HTTPS where available
- Running as non-root user in Docker container
- No sensitive data stored or logged
- Rate limiting through entry count limits

## License

MIT License