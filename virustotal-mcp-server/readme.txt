# VirusTotal MCP Server

A Model Context Protocol (MCP) server that provides comprehensive malware analysis and threat intelligence using the VirusTotal API.

## Purpose

This MCP server enables AI assistants to query VirusTotal for file analysis, URL scanning, IP reputation checks, domain analysis, and threat intelligence searches.

## Features

### Current Implementation

- **`analyze_file_hash`** - Analyze files by MD5, SHA1, or SHA256 hash
- **`scan_url`** - Scan URLs for malicious content and phishing
- **`lookup_ip`** - Get IP address reputation and geolocation info
- **`analyze_domain`** - Analyze domain reputation and registration details
- **`search_virustotal`** - Search VirusTotal intelligence database
- **`get_api_info`** - Check API quota and usage statistics

### VirusTotal API Integration

- Support for both VirusTotal API v2 and v3
- Comprehensive file analysis and malware detection
- URL reputation and safety checking
- IP address and domain intelligence
- Advanced threat hunting capabilities

## Prerequisites

- Docker Desktop with MCP Toolkit enabled
- Docker MCP CLI plugin (`docker mcp` command)
- **VirusTotal API Key** (Required - get from https://www.virustotal.com/gui/my-apikey)

## Installation

### Step 1: Get VirusTotal API Key
1. Sign up at https://www.virustotal.com/
2. Go to https://www.virustotal.com/gui/my-apikey
3. Copy your API key

### Step 2: Set API Key Secret
```bash
docker mcp secret set VIRUSTOTAL_API_KEY="your-api-key-here"
```

### Step 3: Follow remaining installation steps provided

## Usage Examples

In Claude Desktop, you can ask:

- "Analyze this file hash: d41d8cd98f00b204e9800998ecf8427e"
- "Check if this URL is safe: https://example.com"
- "Look up the reputation of IP address 8.8.8.8"
- "Analyze the domain reputation for google.com"
- "Search VirusTotal for files containing 'wannacry'"
- "What's my VirusTotal API usage?"

## Security Use Cases

### Malware Analysis
- Analyze suspicious file hashes
- Check file reputation before execution
- Research malware families and variants

### Threat Hunting
- Search for IoCs (Indicators of Compromise)
- Hunt for specific malware signatures
- Research attack patterns and techniques

### Infrastructure Security
- Verify domain legitimacy
- Check IP address reputation
- Investigate suspicious network activity

### Incident Response
- Validate threat indicators
- Research attack infrastructure
- Correlate threat intelligence

## Architecture

```
Claude Desktop → MCP Gateway → VirusTotal MCP Server → VirusTotal API
                                                      ↓
                              Docker Desktop Secrets (API Key)
```

## Development

### Local Testing

```bash
# Set API key for testing
export VIRUSTOTAL_API_KEY="your-test-key"

# Run directly
python virustotal_server.py

# Test MCP protocol
echo '{"jsonrpc":"2.0","method":"tools/list","id":1}' | python virustotal_server.py
```

### Adding New Tools

1. Add the function to `virustotal_server.py`
2. Decorate with `@mcp.tool()`
3. Update the catalog entry with the new tool name
4. Rebuild the Docker image

## API Rate Limits

- **Free API**: 4 requests per minute, 500 per day
- **Premium API**: Higher limits based on subscription
- Use `get_api_info` tool to monitor usage

## Troubleshooting

### Tools Not Appearing
- Verify Docker image built successfully
- Check catalog and registry files
- Ensure Claude Desktop config includes custom catalog
- Restart Claude Desktop

### Authentication Errors
- Verify API key with `docker mcp secret list`
- Ensure API key is valid at https://www.virustotal.com/gui/my-apikey
- Check API quota with `get_api_info` tool

### API Errors
- Rate limiting: Wait and retry
- Invalid hash format: Use MD5, SHA1, or SHA256
- Not found: Item not in VirusTotal database

## Security Considerations

- API key stored securely in Docker Desktop secrets
- All requests use HTTPS encryption
- No sensitive data logged or cached
- Running as non-root user in container
- Rate limiting respected to prevent abuse

## Data Privacy

- VirusTotal may retain submitted URLs/files
- Consider privacy implications before submitting sensitive data
- Use hash analysis for existing files when possible
- Review VirusTotal's privacy policy

## License

MIT License