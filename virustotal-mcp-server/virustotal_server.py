#!/usr/bin/env python3
"""
VirusTotal MCP Server - Query VirusTotal API for malware analysis and threat intelligence
"""
import os
import sys
import logging
import hashlib
import base64
from datetime import datetime
import httpx
from mcp.server.fastmcp import FastMCP

# Configure logging to stderr
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger("virustotal-server")

# Initialize MCP server - NO PROMPT PARAMETER!
mcp = FastMCP("virustotal")

# Configuration - VirusTotal API
VT_API_BASE = "https://www.virustotal.com/vtapi/v2"
VT_API_V3_BASE = "https://www.virustotal.com/api/v3"
VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")

# === UTILITY FUNCTIONS ===

def get_headers():
    """Get headers for VirusTotal API requests."""
    if not VT_API_KEY:
        raise Exception("VirusTotal API key not configured. Set VIRUSTOTAL_API_KEY environment variable.")
    return {
        "X-Apikey": VT_API_KEY,
        "User-Agent": "VirusTotal-MCP-Server/1.0"
    }

def calculate_file_hashes(content: bytes):
    """Calculate MD5, SHA1, and SHA256 hashes of file content."""
    md5_hash = hashlib.md5(content).hexdigest()
    sha1_hash = hashlib.sha1(content).hexdigest()
    sha256_hash = hashlib.sha256(content).hexdigest()
    return md5_hash, sha1_hash, sha256_hash

def format_scan_results(data: dict) -> str:
    """Format VirusTotal scan results for display."""
    if not data:
        return "❌ No scan data available"
    
    # Handle v2 API response format
    if "scans" in data:
        total_scans = len(data.get("scans", {}))
        positives = data.get("positives", 0)
        scan_date = data.get("scan_date", "Unknown")
        
        result = f"🔍 **VirusTotal Scan Results**\n\n"
        result += f"📊 **Detection Ratio**: {positives}/{total_scans}\n"
        result += f"📅 **Scan Date**: {scan_date}\n"
        result += f"🔗 **Permalink**: {data.get('permalink', 'N/A')}\n\n"
        
        if positives > 0:
            result += f"⚠️ **Detected as Malicious by {positives} engines:**\n"
            for engine, scan_result in data.get("scans", {}).items():
                if scan_result.get("detected"):
                    result += f"  • {engine}: {scan_result.get('result', 'Malware')}\n"
        else:
            result += "✅ **Clean** - No malicious content detected\n"
            
        return result
    
    # Handle v3 API response format
    elif "attributes" in data:
        attrs = data["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0) 
        undetected = stats.get("undetected", 0)
        harmless = stats.get("harmless", 0)
        total = malicious + suspicious + undetected + harmless
        
        result = f"🔍 **VirusTotal Analysis Results**\n\n"
        result += f"📊 **Detection Stats**:\n"
        result += f"  • Malicious: {malicious}\n"
        result += f"  • Suspicious: {suspicious}\n"
        result += f"  • Harmless: {harmless}\n"
        result += f"  • Undetected: {undetected}\n"
        result += f"  • Total: {total}\n\n"
        
        if "last_analysis_date" in attrs:
            scan_date = datetime.fromtimestamp(attrs["last_analysis_date"]).strftime("%Y-%m-%d %H:%M UTC")
            result += f"📅 **Last Analysis**: {scan_date}\n"
        
        if malicious > 0 or suspicious > 0:
            result += f"\n⚠️ **Threat Detected** ({malicious + suspicious} engines)\n"
            
            # Show detection details
            results = attrs.get("last_analysis_results", {})
            detected_engines = []
            for engine, engine_result in results.items():
                if engine_result.get("category") in ["malicious", "suspicious"]:
                    detected_engines.append(f"  • {engine}: {engine_result.get('result', 'Threat')}")
            
            if detected_engines:
                result += "\n".join(detected_engines[:10])  # Show top 10 detections
                if len(detected_engines) > 10:
                    result += f"\n  ... and {len(detected_engines) - 10} more"
        else:
            result += "\n✅ **Clean** - No threats detected\n"
            
        return result
    
    return "❌ Unexpected response format"

def format_url_results(data: dict) -> str:
    """Format URL scan results for display."""
    if "attributes" in data:
        attrs = data["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        
        result = f"🌐 **URL Analysis Results**\n\n"
        result += f"🔗 **URL**: {attrs.get('url', 'N/A')}\n"
        result += f"📊 **Security Vendors Analysis**:\n"
        result += f"  • Malicious: {malicious}\n"
        result += f"  • Suspicious: {suspicious}\n"
        result += f"  • Harmless: {harmless}\n"
        result += f"  • Undetected: {undetected}\n\n"
        
        if "last_analysis_date" in attrs:
            scan_date = datetime.fromtimestamp(attrs["last_analysis_date"]).strftime("%Y-%m-%d %H:%M UTC")
            result += f"📅 **Last Analysis**: {scan_date}\n\n"
        
        if malicious > 0:
            result += f"🚨 **Malicious URL** - Blocked by {malicious} security vendors\n"
        elif suspicious > 0:
            result += f"⚠️ **Suspicious URL** - Flagged by {suspicious} security vendors\n"
        else:
            result += f"✅ **Clean URL** - No threats detected\n"
            
        # Add categories if available
        categories = attrs.get("categories", {})
        if categories:
            result += f"\n🏷️ **Categories**: {', '.join(categories.values())}\n"
            
        return result
    
    return format_scan_results(data)

# === MCP TOOLS ===

@mcp.tool()
async def analyze_file_hash(file_hash: str = "") -> str:
    """Analyze a file hash (MD5, SHA1, or SHA256) using VirusTotal."""
    logger.info(f"Analyzing file hash: {file_hash}")
    
    if not file_hash.strip():
        return "❌ Error: File hash is required"
    
    try:
        headers = get_headers()
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Try v3 API first
            url = f"{VT_API_V3_BASE}/files/{file_hash.strip()}"
            response = await client.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                return f"✅ {format_scan_results(data.get('data', {}))}"
            elif response.status_code == 404:
                return f"📭 File hash not found in VirusTotal database: {file_hash}"
            else:
                # Fallback to v2 API
                url = f"{VT_API_BASE}/file/report"
                params = {"apikey": VT_API_KEY, "resource": file_hash.strip()}
                
                response = await client.get(url, params=params)
                response.raise_for_status()
                
                data = response.json()
                
                if data.get("response_code") == 1:
                    return f"✅ {format_scan_results(data)}"
                elif data.get("response_code") == 0:
                    return f"📭 File hash not found in VirusTotal database: {file_hash}"
                else:
                    return f"❌ Error: {data.get('verbose_msg', 'Unknown error')}"
                    
    except Exception as e:
        logger.error(f"Error analyzing hash: {e}")
        return f"❌ Error analyzing file hash: {str(e)}"

@mcp.tool()
async def scan_url(url: str = "") -> str:
    """Scan a URL for malicious content using VirusTotal."""
    logger.info(f"Scanning URL: {url}")
    
    if not url.strip():
        return "❌ Error: URL is required"
    
    try:
        headers = get_headers()
        target_url = url.strip()
        
        # Encode URL for v3 API
        url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Check existing analysis first
            check_url = f"{VT_API_V3_BASE}/urls/{url_id}"
            response = await client.get(check_url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                return f"✅ {format_url_results(data.get('data', {}))}"
            elif response.status_code == 404:
                # Submit URL for scanning
                submit_url = f"{VT_API_V3_BASE}/urls"
                form_data = {"url": target_url}
                
                response = await client.post(submit_url, headers=headers, data=form_data)
                
                if response.status_code == 200:
                    return f"📤 URL submitted for analysis. Please check again in a few minutes: {target_url}"
                else:
                    response.raise_for_status()
            else:
                response.raise_for_status()
                
    except Exception as e:
        logger.error(f"Error scanning URL: {e}")
        return f"❌ Error scanning URL: {str(e)}"

@mcp.tool()
async def lookup_ip(ip_address: str = "") -> str:
    """Get information about an IP address from VirusTotal."""
    logger.info(f"Looking up IP: {ip_address}")
    
    if not ip_address.strip():
        return "❌ Error: IP address is required"
    
    try:
        headers = get_headers()
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            url = f"{VT_API_V3_BASE}/ip_addresses/{ip_address.strip()}"
            response = await client.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                attrs = data.get("data", {}).get("attributes", {})
                
                result = f"🌐 **IP Address Analysis: {ip_address}**\n\n"
                
                # Basic info
                if "country" in attrs:
                    result += f"🏳️ **Country**: {attrs['country']}\n"
                if "asn" in attrs:
                    result += f"🏢 **ASN**: {attrs['asn']}\n"
                if "as_owner" in attrs:
                    result += f"👤 **AS Owner**: {attrs['as_owner']}\n"
                
                # Reputation
                rep_stats = attrs.get("last_analysis_stats", {})
                if rep_stats:
                    malicious = rep_stats.get("malicious", 0)
                    suspicious = rep_stats.get("suspicious", 0)
                    harmless = rep_stats.get("harmless", 0)
                    
                    result += f"\n📊 **Reputation Analysis**:\n"
                    result += f"  • Malicious: {malicious}\n"
                    result += f"  • Suspicious: {suspicious}\n"
                    result += f"  • Harmless: {harmless}\n"
                    
                    if malicious > 0:
                        result += f"\n🚨 **Malicious IP** - Flagged by {malicious} security vendors\n"
                    elif suspicious > 0:
                        result += f"\n⚠️ **Suspicious IP** - Flagged by {suspicious} security vendors\n"
                    else:
                        result += f"\n✅ **Clean IP** - No threats detected\n"
                
                return f"✅ {result}"
            elif response.status_code == 404:
                return f"📭 IP address not found in VirusTotal database: {ip_address}"
            else:
                response.raise_for_status()
                
    except Exception as e:
        logger.error(f"Error looking up IP: {e}")
        return f"❌ Error looking up IP address: {str(e)}"

@mcp.tool()
async def analyze_domain(domain: str = "") -> str:
    """Analyze a domain name using VirusTotal."""
    logger.info(f"Analyzing domain: {domain}")
    
    if not domain.strip():
        return "❌ Error: Domain name is required"
    
    try:
        headers = get_headers()
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            url = f"{VT_API_V3_BASE}/domains/{domain.strip()}"
            response = await client.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                attrs = data.get("data", {}).get("attributes", {})
                
                result = f"🌍 **Domain Analysis: {domain}**\n\n"
                
                # Basic info
                if "creation_date" in attrs:
                    creation_date = datetime.fromtimestamp(attrs["creation_date"]).strftime("%Y-%m-%d")
                    result += f"📅 **Created**: {creation_date}\n"
                
                if "registrar" in attrs:
                    result += f"🏢 **Registrar**: {attrs['registrar']}\n"
                
                # Reputation
                rep_stats = attrs.get("last_analysis_stats", {})
                if rep_stats:
                    malicious = rep_stats.get("malicious", 0)
                    suspicious = rep_stats.get("suspicious", 0) 
                    harmless = rep_stats.get("harmless", 0)
                    undetected = rep_stats.get("undetected", 0)
                    
                    result += f"\n📊 **Security Analysis**:\n"
                    result += f"  • Malicious: {malicious}\n"
                    result += f"  • Suspicious: {suspicious}\n"
                    result += f"  • Harmless: {harmless}\n"
                    result += f"  • Undetected: {undetected}\n"
                    
                    if malicious > 0:
                        result += f"\n🚨 **Malicious Domain** - Flagged by {malicious} security vendors\n"
                    elif suspicious > 0:
                        result += f"\n⚠️ **Suspicious Domain** - Flagged by {suspicious} security vendors\n"  
                    else:
                        result += f"\n✅ **Clean Domain** - No threats detected\n"
                
                # Categories
                categories = attrs.get("categories", {})
                if categories:
                    result += f"\n🏷️ **Categories**: {', '.join(categories.values())}\n"
                
                return f"✅ {result}"
            elif response.status_code == 404:
                return f"📭 Domain not found in VirusTotal database: {domain}"
            else:
                response.raise_for_status()
                
    except Exception as e:
        logger.error(f"Error analyzing domain: {e}")
        return f"❌ Error analyzing domain: {str(e)}"

@mcp.tool()
async def search_virustotal(query: str = "", limit: str = "10") -> str:
    """Search VirusTotal intelligence for files, URLs, domains, or IPs."""
    logger.info(f"Searching VirusTotal for: {query}")
    
    if not query.strip():
        return "❌ Error: Search query is required"
    
    try:
        headers = get_headers() 
        limit_int = int(limit) if limit.strip() and limit.strip().isdigit() else 10
        limit_int = min(limit_int, 20)  # Cap at 20 results
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            url = f"{VT_API_V3_BASE}/intelligence/search"
            params = {
                "query": query.strip(),
                "limit": limit_int
            }
            
            response = await client.get(url, headers=headers, params=params)
            
            if response.status_code == 200:
                data = response.json()
                results = data.get("data", [])
                
                if not results:
                    return f"🔍 No results found for query: '{query}'"
                
                result = f"🔍 **VirusTotal Search Results for '{query}'**\n\n"
                result += f"Found {len(results)} results:\n\n"
                
                for i, item in enumerate(results, 1):
                    item_type = item.get("type", "unknown")
                    item_id = item.get("id", "N/A")
                    attrs = item.get("attributes", {})
                    
                    result += f"**{i}. {item_type.upper()}: {item_id}**\n"
                    
                    if item_type == "file":
                        stats = attrs.get("last_analysis_stats", {})
                        malicious = stats.get("malicious", 0)
                        result += f"   🔍 Detections: {malicious}\n"
                        if "meaningful_name" in attrs:
                            result += f"   📄 Name: {attrs['meaningful_name']}\n"
                    elif item_type == "url":
                        stats = attrs.get("last_analysis_stats", {})
                        malicious = stats.get("malicious", 0)
                        result += f"   🔍 Detections: {malicious}\n"
                        result += f"   🔗 URL: {attrs.get('url', 'N/A')[:80]}...\n"
                    elif item_type in ["domain", "ip_address"]:
                        stats = attrs.get("last_analysis_stats", {})
                        malicious = stats.get("malicious", 0)
                        result += f"   🔍 Detections: {malicious}\n"
                    
                    result += "\n"
                
                return f"✅ {result}"
            else:
                response.raise_for_status()
                
    except Exception as e:
        logger.error(f"Error searching VirusTotal: {e}")
        return f"❌ Error searching VirusTotal: {str(e)}"

@mcp.tool()
async def get_api_info() -> str:
    """Get VirusTotal API quota and usage information."""
    logger.info("Getting VirusTotal API information")
    
    try:
        headers = get_headers()
        
        async with httpx.AsyncClient(timeout=15.0) as client:
            url = f"{VT_API_V3_BASE}/users/self"
            response = await client.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                attrs = data.get("data", {}).get("attributes", {})
                
                result = f"ℹ️ **VirusTotal API Information**\n\n"
                
                if "quotas" in attrs:
                    quotas = attrs["quotas"]
                    for quota_type, quota_info in quotas.items():
                        used = quota_info.get("used", 0)
                        allowed = quota_info.get("allowed", 0)
                        result += f"📊 **{quota_type}**: {used}/{allowed}\n"
                
                return f"✅ {result}"
            else:
                response.raise_for_status()
                
    except Exception as e:
        logger.error(f"Error getting API info: {e}")
        return f"❌ Error getting API information: {str(e)}"

# === SERVER STARTUP ===
if __name__ == "__main__":
    logger.info("Starting VirusTotal MCP server...")
    
    if not VT_API_KEY:
        logger.warning("VIRUSTOTAL_API_KEY not set - server will not function without API key")
    else:
        logger.info("VirusTotal API key configured")
    
    try:
        mcp.run(transport='stdio')
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
        sys.exit(1)