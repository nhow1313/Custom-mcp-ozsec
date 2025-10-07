#!/usr/bin/env python3
"""
RSS Feed MCP Server - Query cybersecurity RSS feeds for latest articles
"""
import os
import sys
import logging
from datetime import datetime, timezone
import httpx
import feedparser
from dateutil import parser as date_parser
from mcp.server.fastmcp import FastMCP

# Configure logging to stderr
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger("rss-feed-server")

# Initialize MCP server - NO PROMPT PARAMETER!
mcp = FastMCP("rss-feed")

# Configuration - RSS Feed URLs
RSS_FEEDS = {
    "krebs": "https://krebsonsecurity.com/feed",
    "schneier": "https://schneier.com/tag/cybersecurity/feed", 
    "exploitdb": "https://www.exploit-db.com/rss.xml"
}

# === UTILITY FUNCTIONS ===

async def fetch_rss_feed(url: str, max_entries: int = 10):
    """Fetch and parse an RSS feed."""
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(url, follow_redirects=True)
            response.raise_for_status()
            
            # Parse RSS feed
            feed = feedparser.parse(response.content)
            
            if feed.bozo and hasattr(feed, 'bozo_exception'):
                logger.warning(f"Feed parsing warning for {url}: {feed.bozo_exception}")
            
            entries = []
            for entry in feed.entries[:max_entries]:
                # Parse published date
                published_date = "Unknown date"
                if hasattr(entry, 'published'):
                    try:
                        parsed_date = date_parser.parse(entry.published)
                        published_date = parsed_date.strftime("%Y-%m-%d %H:%M UTC")
                    except:
                        published_date = entry.published
                
                # Get summary/description
                summary = ""
                if hasattr(entry, 'summary'):
                    summary = entry.summary[:300] + "..." if len(entry.summary) > 300 else entry.summary
                elif hasattr(entry, 'description'):
                    summary = entry.description[:300] + "..." if len(entry.description) > 300 else entry.description
                
                entries.append({
                    'title': entry.title if hasattr(entry, 'title') else 'No title',
                    'link': entry.link if hasattr(entry, 'link') else '',
                    'published': published_date,
                    'summary': summary
                })
            
            return {
                'feed_title': feed.feed.title if hasattr(feed.feed, 'title') else 'RSS Feed',
                'feed_description': feed.feed.description if hasattr(feed.feed, 'description') else '',
                'entries': entries
            }
            
    except httpx.HTTPStatusError as e:
        raise Exception(f"HTTP error {e.response.status_code}: {e.response.reason_phrase}")
    except Exception as e:
        raise Exception(f"Error fetching feed: {str(e)}")

def format_feed_entries(feed_data: dict, limit: int = 10) -> str:
    """Format RSS feed entries for display."""
    entries = feed_data['entries'][:limit]
    
    result = f"📰 **{feed_data['feed_title']}**\n"
    if feed_data['feed_description']:
        result += f"{feed_data['feed_description']}\n"
    result += f"\n📊 Showing {len(entries)} latest articles:\n\n"
    
    for i, entry in enumerate(entries, 1):
        result += f"**{i}. {entry['title']}**\n"
        result += f"🔗 {entry['link']}\n"
        result += f"📅 {entry['published']}\n"
        if entry['summary']:
            result += f"📝 {entry['summary']}\n"
        result += "\n"
    
    return result

# === MCP TOOLS ===

@mcp.tool()
async def get_krebs_feed(limit: str = "10") -> str:
    """Get latest articles from Krebs on Security RSS feed."""
    logger.info(f"Fetching Krebs on Security feed with limit {limit}")
    
    try:
        limit_int = int(limit) if limit.strip() and limit.strip().isdigit() else 10
        limit_int = min(limit_int, 25)  # Cap at 25 entries
        
        feed_data = await fetch_rss_feed(RSS_FEEDS["krebs"], limit_int)
        formatted_result = format_feed_entries(feed_data, limit_int)
        
        return f"✅ **Krebs on Security Feed**\n\n{formatted_result}"
        
    except Exception as e:
        logger.error(f"Error fetching Krebs feed: {e}")
        return f"❌ Error fetching Krebs on Security feed: {str(e)}"

@mcp.tool()
async def get_schneier_feed(limit: str = "10") -> str:
    """Get latest cybersecurity articles from Bruce Schneier's RSS feed."""
    logger.info(f"Fetching Schneier cybersecurity feed with limit {limit}")
    
    try:
        limit_int = int(limit) if limit.strip() and limit.strip().isdigit() else 10
        limit_int = min(limit_int, 25)  # Cap at 25 entries
        
        feed_data = await fetch_rss_feed(RSS_FEEDS["schneier"], limit_int)
        formatted_result = format_feed_entries(feed_data, limit_int)
        
        return f"✅ **Bruce Schneier - Cybersecurity Feed**\n\n{formatted_result}"
        
    except Exception as e:
        logger.error(f"Error fetching Schneier feed: {e}")
        return f"❌ Error fetching Schneier cybersecurity feed: {str(e)}"

@mcp.tool()
async def get_exploitdb_feed(limit: str = "10") -> str:
    """Get latest exploits and security advisories from Exploit-DB RSS feed."""
    logger.info(f"Fetching Exploit-DB feed with limit {limit}")
    
    try:
        limit_int = int(limit) if limit.strip() and limit.strip().isdigit() else 10
        limit_int = min(limit_int, 25)  # Cap at 25 entries
        
        feed_data = await fetch_rss_feed(RSS_FEEDS["exploitdb"], limit_int)
        formatted_result = format_feed_entries(feed_data, limit_int)
        
        return f"✅ **Exploit-DB Latest Exploits**\n\n{formatted_result}"
        
    except Exception as e:
        logger.error(f"Error fetching Exploit-DB feed: {e}")
        return f"❌ Error fetching Exploit-DB feed: {str(e)}"

@mcp.tool()
async def get_all_feeds_summary(limit: str = "5") -> str:
    """Get a summary of latest articles from all cybersecurity RSS feeds."""
    logger.info(f"Fetching summary from all feeds with limit {limit}")
    
    try:
        limit_int = int(limit) if limit.strip() and limit.strip().isdigit() else 5
        limit_int = min(limit_int, 10)  # Cap at 10 entries per feed for summary
        
        results = []
        
        # Fetch all feeds
        for feed_name, feed_url in RSS_FEEDS.items():
            try:
                feed_data = await fetch_rss_feed(feed_url, limit_int)
                results.append({
                    'name': feed_name,
                    'title': feed_data['feed_title'],
                    'entries': feed_data['entries'][:limit_int]
                })
            except Exception as e:
                logger.error(f"Error fetching {feed_name} feed: {e}")
                results.append({
                    'name': feed_name,
                    'title': f"{feed_name} (Error)",
                    'entries': [],
                    'error': str(e)
                })
        
        # Format combined results
        summary = "🌐 **Cybersecurity RSS Feeds Summary**\n\n"
        
        for result in results:
            summary += f"📰 **{result['title']}**\n"
            
            if 'error' in result:
                summary += f"❌ Error: {result['error']}\n\n"
                continue
                
            if not result['entries']:
                summary += "No articles found.\n\n"
                continue
                
            for i, entry in enumerate(result['entries'], 1):
                summary += f"{i}. {entry['title']}\n"
                summary += f"   🔗 {entry['link']}\n"
                summary += f"   📅 {entry['published']}\n"
            summary += "\n"
        
        return f"✅ {summary}"
        
    except Exception as e:
        logger.error(f"Error fetching feed summary: {e}")
        return f"❌ Error fetching feeds summary: {str(e)}"

@mcp.tool()
async def search_feeds(query: str = "", limit: str = "10") -> str:
    """Search for articles containing specific keywords across all RSS feeds."""
    logger.info(f"Searching feeds for query: {query}")
    
    if not query.strip():
        return "❌ Error: Search query is required"
    
    try:
        limit_int = int(limit) if limit.strip() and limit.strip().isdigit() else 10
        search_query = query.strip().lower()
        
        all_matches = []
        
        # Search all feeds
        for feed_name, feed_url in RSS_FEEDS.items():
            try:
                feed_data = await fetch_rss_feed(feed_url, 25)  # Get more entries for searching
                
                for entry in feed_data['entries']:
                    # Search in title and summary
                    title_match = search_query in entry['title'].lower()
                    summary_match = search_query in entry['summary'].lower() if entry['summary'] else False
                    
                    if title_match or summary_match:
                        all_matches.append({
                            'feed': feed_data['feed_title'],
                            'title': entry['title'],
                            'link': entry['link'],
                            'published': entry['published'],
                            'summary': entry['summary']
                        })
                        
            except Exception as e:
                logger.error(f"Error searching {feed_name} feed: {e}")
                continue
        
        # Sort by relevance (title matches first)
        all_matches.sort(key=lambda x: search_query in x['title'].lower(), reverse=True)
        
        # Limit results
        matches = all_matches[:limit_int]
        
        if not matches:
            return f"🔍 No articles found containing '{query}'"
        
        result = f"🔍 **Search Results for '{query}'**\n\n"
        result += f"Found {len(all_matches)} total matches, showing top {len(matches)}:\n\n"
        
        for i, match in enumerate(matches, 1):
            result += f"**{i}. {match['title']}**\n"
            result += f"📰 From: {match['feed']}\n"
            result += f"🔗 {match['link']}\n"
            result += f"📅 {match['published']}\n"
            if match['summary']:
                result += f"📝 {match['summary']}\n"
            result += "\n"
        
        return f"✅ {result}"
        
    except Exception as e:
        logger.error(f"Error searching feeds: {e}")
        return f"❌ Error searching feeds: {str(e)}"

# === SERVER STARTUP ===
if __name__ == "__main__":
    logger.info("Starting RSS Feed MCP server...")
    
    # Validate feed URLs
    logger.info("RSS feeds configured:")
    for name, url in RSS_FEEDS.items():
        logger.info(f"  {name}: {url}")
    
    try:
        mcp.run(transport='stdio')
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
        sys.exit(1)