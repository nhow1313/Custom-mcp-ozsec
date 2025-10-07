# VirusTotal MCP Server - Claude Integration Guide

## Overview

This MCP server enables Claude to perform comprehensive malware analysis and threat intelligence using the VirusTotal API, providing access to one of the world's largest malware databases.

## Available Tools

### 1. analyze_file_hash(file_hash="")
Analyzes files using their cryptographic hashes.
- **file_hash**: MD5, SHA1, or SHA256 hash (required)
- Returns detailed malware scan results from multiple antivirus engines

### 2. scan_url(url="")
Scans URLs for malicious content and phishing attempts.
- **url**: Full URL to analyze (required)
- Returns safety analysis and threat categorization

### 3. lookup_ip(ip_address="")
Provides reputation and intelligence data for IP addresses.
- **ip_address**: IPv4 or IPv6 address (required)  
- Returns geolocation, ASN info, and malicious activity reports

### 4. analyze_domain(domain="")
Analyzes domain names for reputation and security threats.
- **domain**: Domain name to analyze (required)
- Returns registration info, categories, and threat analysis

### 5. search_virustotal(query="", limit="10")
Searches the VirusTotal intelligence database.
- **query**: Search terms or IoCs (required)
- **limit**: Maximum results to return (1-20, default: 10)

### 6. get_api_info()
Displays current API quota usage and limits.
- No parameters required
- Returns quota status and usage statistics

## Implementation Details

### API Integration
- **VirusTotal API v3**: Primary API with advanced features
- **VirusTotal API v2**: Fallback for legacy compatibility
- **Rate Limiting**: Respects API quotas (4/min free, 500/day)
- **Authentication**: Secure API key management via Docker secrets

### Supported Hash Types
- **MD5**: 32-character hexadecimal
- **SHA1**: 40-character hexadecimal  
- **SHA256**: 64-character hexadecimal

### Detection Analysis
- **Malicious**: Confirmed threats by security engines
- **Suspicious**: Potentially harmful content
- **Harmless**: Legitimate, safe content
- **Undetected**: Not flagged by any engine

### Search Capabilities
- File hashes and malware signatures
- Domain names and subdomains
- IP addresses and CIDR ranges
- URLs and web resources
- YARA rules and custom indicators

## Usage Patterns

### Malware Analysis
```
"Analyze this suspicious file hash: a1b2c3d4e5f6..."
"Is this file malicious: 5d41402abc4b2a76b9719d911017c592"
```

### URL Safety Verification  
```
"Check if this URL is safe: https://suspicious-site.com"
"Scan this link for malware: http://example.com/download"
```

### Threat Intelligence
```
"Look up reputation for IP 192.168.1.1"
"Analyze domain reputation: malicious-domain.com" 
"Search for wannacry malware samples"
```

### Incident Response
```
"Search VirusTotal for indicators related to APT28"
"Find recent samples of ransomware family"
"Check API quota usage"
```

## Technical Features

### Response Formatting
- **Detection Ratios**: Clear X/Y format showing threats found
- **Scan Dates**: Human-readable timestamps
- **Engine Details**: Specific antivirus engine results  
- **Threat Categories**: Malware family classification
- **Geolocation Data**: Country and ASN information

### Error Handling
- **Rate Limiting**: Graceful handling with retry suggestions
- **Invalid Hashes**: Format validation and error messages
- **Not Found**: Clear messaging for unknown items
- **API Errors**: Detailed error reporting and troubleshooting

### Security Features
- **Secure Authentication**: API keys stored in Docker secrets
- **HTTPS Only**: All API communications encrypted
- **No Data Retention**: No caching of sensitive results
- **Request Logging**: Minimal logging for debugging only

## Best Practices

### Hash Analysis (Preferred)
1. **Use hashes when possible** - Avoids uploading sensitive files
2. **Multiple hash types** - Try SHA256, SHA1, then MD5
3. **Verify results** - Cross-reference with multiple engines

### URL Scanning (Use Carefully)
1. **Consider privacy** - URLs are submitted to VirusTotal
2. **Check existing results** - May already be analyzed
3. **Avoid sensitive URLs** - Don't submit internal/private links

### API Usage Management
1. **Monitor quotas** - Use get_api_info regularly
2. **Batch requests** - Group related queries efficiently  
3. **Cache results** - Avoid re-analyzing same items
4. **Respect limits** - Free API has 4 requests/minute limit

## Integration Examples

### Security Operations
- Automated threat analysis in incident response
- IoC validation and threat hunting
- Malware family research and attribution
- Phishing URL analysis and blocking

### Development Security
- File integrity verification
- Dependency scanning for malicious packages
- URL validation in web applications
- Security research and analysis

## Limitations

### API Constraints
- **Rate Limits**: Free accounts limited to 4 req/min
- **File Size**: 32MB limit for file uploads via API
- **History**: Limited historical data for free accounts
- **Advanced Features**: Some features require premium subscription

### Privacy Considerations
- **Data Retention**: VirusTotal retains submitted content
- **Public Database**: Results may be publicly searchable
- **Attribution**: Submissions linked to API key owner
- **Legal**: Ensure compliance with data handling regulations

## Error Reference

### Common Error Codes
- **403 Forbidden**: Invalid or missing API key
- **429 Too Many Requests**: Rate limit exceeded
- **404 Not Found**: Hash/URL not in database
- **400 Bad Request**: Invalid hash format or parameters

### Troubleshooting Steps
1. Verify API key is set correctly
2. Check current quota with get_api_info
3. Validate hash format (32/40/64 hex characters)
4. Wait if rate limited (4 requests per minute)
5. Ensure network connectivity to VirusTotal

## Advanced Features

### Intelligence Search Operators
- **File searches**: `type:peexe size:1MB+`
- **Domain searches**: `entity:domain engines:5+`
- **IP searches**: `type:ip_address country:US`
- **Time ranges**: `first_seen:2024-01-01+ last_seen:2024-12-31-`

### Premium Features (Subscription Required)
- **LiveHunt**: Real-time malware hunting
- **Retrohunt**: Historical malware scanning  
- **Graph API**: Relationship analysis
- **Advanced Search**: Complex query operators
- **Bulk Operations**: Mass analysis capabilities