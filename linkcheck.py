import aiohttp
import asyncio
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlunparse
from collections import deque
import csv
from tqdm import tqdm
import concurrent.futures
import time
from typing import Set, List, Tuple, Optional, Dict, Any
import logging
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
import re
import argparse
from colorama import init, Fore, Style
import json
import os
from datetime import datetime
import hashlib
import aiofiles
from urllib.robotparser import RobotFileParser
import xml.etree.ElementTree as ET
import ssl
import certifi
import gc
from dataclasses import dataclass, asdict
from enum import Enum
import tracemalloc
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.panel import Panel
from rich.text import Text
from rich import print as rprint
import platform
import pathlib
import sys

# Initialize colorama for Windows support
init()

# Get the user's home directory in a cross-platform way
HOME_DIR = str(pathlib.Path.home())
APP_NAME = "LinkGuardian"
APP_DIR = os.path.join(HOME_DIR, f".{APP_NAME.lower()}")

# Configure logging with more detail
def setup_logging():
    """Setup logging with platform-specific paths."""
    log_dir = os.path.join(APP_DIR, "logs")
    os.makedirs(log_dir, exist_ok=True)
    
    log_file = os.path.join(log_dir, "linkchecker.log")
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

logger = setup_logging()

# Configure event loop policy based on platform
def setup_event_loop():
    """Configure event loop policy based on the operating system."""
    if platform.system() == 'Windows':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    elif platform.system() == 'Darwin':  # macOS
        # Use the default event loop policy for macOS
        pass
    else:  # Linux and others
        # Use the default event loop policy
        pass

setup_event_loop()

def normalize_path(path: str) -> str:
    """Normalize path for the current operating system."""
    return os.path.normpath(path)

def get_cache_dir() -> str:
    """Get the cache directory path based on the operating system."""
    cache_dir = os.path.join(APP_DIR, "cache")
    os.makedirs(cache_dir, exist_ok=True)
    return cache_dir

def get_output_dir() -> str:
    """Get the output directory path based on the operating system."""
    output_dir = os.path.join(APP_DIR, "output")
    os.makedirs(output_dir, exist_ok=True)
    return output_dir

class LinkType(Enum):
    INTERNAL = "internal"
    EXTERNAL = "external"
    RESOURCE = "resource"

class ErrorCategory(Enum):
    CONNECTION = "connection"
    TIMEOUT = "timeout"
    SSL = "ssl"
    HTTP = "http"
    PARSING = "parsing"
    VALIDATION = "validation"
    UNKNOWN = "unknown"

@dataclass
class LinkInfo:
    url: str
    source_url: str
    status: str
    link_type: LinkType
    depth: int
    timestamp: str
    error_category: Optional[ErrorCategory] = None
    content_hash: Optional[str] = None
    meta_tags: Dict[str, str] = None
    is_orphaned: bool = False
    redirect_chain: List[str] = None

class LinkChecker:
    def __init__(self, base_url: str, max_workers: int = 10, rate_limit: float = 1.0, 
                 max_pages: int = 100, max_depth: int = 3, cache_dir: str = None):
        self.base_url = base_url
        self.domain = urlparse(base_url).netloc
        self.visited_pages: Set[str] = set()
        self.checked_links: Set[str] = set()
        self.broken_links: List[LinkInfo] = []
        self.all_links: List[LinkInfo] = []
        self.max_workers = max_workers
        self.rate_limit = rate_limit
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.page_depths: Dict[str, int] = {base_url: 0}
        self.cache_dir = cache_dir or get_cache_dir()
        self.robots_parser = RobotFileParser()
        self.ssl_context = ssl.create_default_context(cafile=certifi.where())
        self.session = None
        self._setup_cache()
        
    def _setup_cache(self):
        """Setup cache directory and load existing cache if available."""
        os.makedirs(self.cache_dir, exist_ok=True)
        self.cache_file = os.path.join(self.cache_dir, f"{self.domain.replace('.', '_')}_cache.json")
        self._load_cache()
        
    def _load_cache(self):
        """Load cached data if available."""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    cache_data = json.load(f)
                    self.visited_pages = set(cache_data.get('visited_pages', []))
                    self.checked_links = set(cache_data.get('checked_links', []))
                    
                    # Convert string values back to enums when loading
                    all_links_data = []
                    for link_dict in cache_data.get('all_links', []):
                        # Convert string values back to enums
                        link_dict['link_type'] = LinkType(link_dict['link_type'])
                        if link_dict.get('error_category'):
                            link_dict['error_category'] = ErrorCategory(link_dict['error_category'])
                        all_links_data.append(LinkInfo(**link_dict))
                    
                    self.all_links = all_links_data
                    self.broken_links = [link for link in self.all_links if 
                                      (link.status.isdigit() and int(link.status) >= 400) or 
                                      not link.status.isdigit()]
                    logger.info(f"Loaded cache with {len(self.visited_pages)} visited pages")
        except Exception as e:
            logger.error(f"Error loading cache: {e}")
            
    def _save_cache(self):
        """Save current state to cache."""
        try:
            # Convert LinkInfo objects to dictionaries with enum values converted to strings
            all_links_data = []
            for link in self.all_links:
                link_dict = asdict(link)
                # Convert enum values to strings
                link_dict['link_type'] = link_dict['link_type'].value
                if link_dict.get('error_category'):
                    link_dict['error_category'] = link_dict['error_category'].value
                all_links_data.append(link_dict)

            cache_data = {
                'visited_pages': list(self.visited_pages),
                'checked_links': list(self.checked_links),
                'all_links': all_links_data,
                'timestamp': datetime.now().isoformat()
            }
            with open(self.cache_file, 'w') as f:
                json.dump(cache_data, f)
            logger.info("Cache saved successfully")
        except Exception as e:
            logger.error(f"Error saving cache: {e}")

    async def _create_session(self):
        """Create an aiohttp session with SSL context."""
        if not self.session:
            self.session = aiohttp.ClientSession(
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
                },
                timeout=aiohttp.ClientTimeout(total=30),
                connector=aiohttp.TCPConnector(ssl=self.ssl_context)
            )

    async def _fetch_robots_txt(self):
        """Fetch and parse robots.txt file."""
        try:
            robots_url = urljoin(self.base_url, '/robots.txt')
            async with self.session.get(robots_url) as response:
                if response.status == 200:
                    content = await response.text()
                    self.robots_parser.parse(content.splitlines())
                    logger.info("Successfully parsed robots.txt")
                else:
                    logger.warning(f"Could not fetch robots.txt: {response.status}")
        except Exception as e:
            logger.error(f"Error fetching robots.txt: {e}")

    async def _fetch_sitemap(self) -> Set[str]:
        """Fetch and parse sitemap.xml file."""
        urls = set()
        try:
            sitemap_url = urljoin(self.base_url, '/sitemap.xml')
            async with self.session.get(sitemap_url) as response:
                if response.status == 200:
                    content = await response.text()
                    root = ET.fromstring(content)
                    for url in root.findall('.//{http://www.sitemaps.org/schemas/sitemap/0.9}url'):
                        loc = url.find('{http://www.sitemaps.org/schemas/sitemap/0.9}loc')
                        if loc is not None and loc.text:
                            urls.add(loc.text)
                    logger.info(f"Found {len(urls)} URLs in sitemap.xml")
                else:
                    logger.warning(f"Could not fetch sitemap.xml: {response.status}")
        except Exception as e:
            logger.error(f"Error fetching sitemap.xml: {e}")
        return urls

    def _normalize_url(self, url: str) -> str:
        """Normalize URL by removing fragments and query parameters."""
        parsed = urlparse(url)
        return urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            '',
            '',
            ''
        ))

    def _is_valid_url(self, url: str) -> bool:
        """Check if URL is valid and belongs to the same domain."""
        try:
            parsed = urlparse(url)
            return (
                parsed.netloc == self.domain
                and parsed.scheme in ('http', 'https')
                and not any(ext in url.lower() for ext in ['.pdf', '.jpg', '.jpeg', '.png', '.gif', '.svg'])
            )
        except:
            return False

    async def _get_content_hash(self, content: str) -> str:
        """Calculate hash of content for duplicate detection."""
        return hashlib.md5(content.encode()).hexdigest()

    async def get_links(self, url: str) -> Set[str]:
        """Extract all valid links from a webpage."""
        try:
            async with self.session.get(url) as response:
                if response.status != 200:
                    logger.error(f"Error fetching {url}: {response.status}")
                    return set()
                
                content = await response.text()
                soup = BeautifulSoup(content, "html.parser")
                links = set()
                
                # Check for duplicate content
                content_hash = await self._get_content_hash(content)
                
                for link in soup.find_all("a", href=True):
                    href = link.get("href")
                    if not href:
                        continue
                        
                    full_url = urljoin(url, href)
                    normalized_url = self._normalize_url(full_url)
                    
                    if self._is_valid_url(normalized_url):
                        links.add(normalized_url)
                
                return links
                
        except Exception as e:
            logger.error(f"Error fetching {url}: {str(e)}")
            return set()

    async def check_link(self, url: str, source_url: str, depth: int) -> LinkInfo:
        """Check a URL and return its status with detailed information."""
        try:
            async with self.session.head(url, allow_redirects=True) as response:
                status = str(response.status)
                redirect_chain = [r.url for r in response.history]
                
                link_info = LinkInfo(
                    url=url,
                    source_url=source_url,
                    status=status,
                    link_type=LinkType.INTERNAL if urlparse(url).netloc == self.domain else LinkType.EXTERNAL,
                    depth=depth,
                    timestamp=datetime.now().isoformat(),
                    redirect_chain=redirect_chain
                )
                
                if response.status >= 400:
                    link_info.error_category = ErrorCategory.HTTP
                    self.broken_links.append(link_info)
                
                return link_info
                
        except aiohttp.ClientError as e:
            error_category = ErrorCategory.CONNECTION
            if isinstance(e, asyncio.TimeoutError):
                error_category = ErrorCategory.TIMEOUT
            elif isinstance(e, ssl.SSLError):
                error_category = ErrorCategory.SSL
                
            link_info = LinkInfo(
                url=url,
                source_url=source_url,
                status=str(e),
                link_type=LinkType.INTERNAL if urlparse(url).netloc == self.domain else LinkType.EXTERNAL,
                depth=depth,
                timestamp=datetime.now().isoformat(),
                error_category=error_category
            )
            self.broken_links.append(link_info)
            return link_info

    async def process_page(self, url: str) -> Set[str]:
        """Process a single page and return new links to check."""
        if url in self.visited_pages:
            return set()
            
        self.visited_pages.add(url)
        logger.debug(f"Processing: {url}")
        
        # Get all links on the page
        links = await self.get_links(url)
        
        # Filter out already checked links
        links_to_check = {link for link in links if link not in self.checked_links}
        
        # Check links concurrently
        tasks = []
        for link in links_to_check:
            task = asyncio.create_task(self.check_link(link, url, self.page_depths.get(url, 0)))
            tasks.append(task)
        
        results = await asyncio.gather(*tasks)
        for result in results:
            self.checked_links.add(result.url)
            self.all_links.append(result)
        
        # Calculate depth for new pages
        current_depth = self.page_depths.get(url, 0)
        for link in links:
            if link not in self.page_depths:
                self.page_depths[link] = current_depth + 1
        
        return links

    async def crawl_website(self):
        """Crawl the website and find broken links."""
        await self._create_session()
        await self._fetch_robots_txt()
        
        # Get initial URLs from sitemap
        sitemap_urls = await self._fetch_sitemap()
        queue = deque([self.base_url] + list(sitemap_urls))
        
        with tqdm(desc="Crawling Pages", unit="page") as pbar:
            while queue and len(self.visited_pages) < self.max_pages:
                current_url = queue.popleft()
                current_depth = self.page_depths.get(current_url, 0)
                
                # Skip pages beyond max depth
                if current_depth > self.max_depth:
                    continue
                
                # Check robots.txt
                if not self.robots_parser.can_fetch("*", current_url):
                    logger.info(f"Skipping {current_url} due to robots.txt")
                    continue
                
                # Process the current page
                new_links = await self.process_page(current_url)
                
                # Add new links to queue
                for link in new_links:
                    if link not in self.visited_pages:
                        queue.append(link)
                
                # Update progress
                pbar.total = min(self.max_pages, max(pbar.total or 0, len(self.visited_pages) + len(queue)))
                pbar.update(1)
                pbar.set_postfix({
                    "depth": current_depth,
                    "queue": len(queue),
                    "broken": len(self.broken_links)
                })
                
                # Rate limiting
                await asyncio.sleep(self.rate_limit)
                
                # Save cache periodically
                if len(self.visited_pages) % 10 == 0:
                    self._save_cache()
                
                # Check if we've reached the maximum number of pages
                if len(self.visited_pages) >= self.max_pages:
                    logger.info(f"Reached maximum number of pages ({self.max_pages})")
                    break

    async def analyze_results(self):
        """Analyze the crawl results."""
        # Find orphaned pages
        all_urls = {link.url for link in self.all_links}
        source_urls = {link.source_url for link in self.all_links}
        orphaned = all_urls - source_urls - {self.base_url}
        
        for url in orphaned:
            for link in self.all_links:
                if link.url == url:
                    link.is_orphaned = True
                    break
        
        # Analyze link structure
        internal_links = [link for link in self.all_links if link.link_type == LinkType.INTERNAL]
        external_links = [link for link in self.all_links if link.link_type == LinkType.EXTERNAL]
        
        # Display results in terminal with colors
        console = Console()
        console.print("\n[bold cyan]Analysis Results:[/bold cyan]")
        console.print(f"[green]Total pages:[/green] {len(self.visited_pages)}")
        console.print(f"[blue]Internal links:[/blue] {len(internal_links)}")
        console.print(f"[yellow]External links:[/yellow] {len(external_links)}")
        console.print(f"[red]Orphaned pages:[/red] {len(orphaned)}")
        console.print(f"[red]Broken links:[/red] {len(self.broken_links)}")
        
        # Display links in terminal
        console.print("\n[bold cyan]Discovered Links:[/bold cyan]")
        for link in self.all_links:
            status_color = "red" if link.status.isdigit() and int(link.status) >= 400 else "green"
            link_type_color = "blue" if link.link_type == LinkType.INTERNAL else "yellow"
            orphaned_color = "red" if link.is_orphaned else "green"
            
            console.print(f"[{status_color}]Status: {link.status}[/{status_color}] | "
                         f"[{link_type_color}]Type: {link.link_type.value}[/{link_type_color}] | "
                         f"[{orphaned_color}]Orphaned: {link.is_orphaned}[/{orphaned_color}] | "
                         f"[white]URL: {link.url}[/white]")

    async def save_results(self):
        """Save results to CSV files."""
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        domain = urlparse(self.base_url).netloc.replace('.', '_')
        
        # Create output directory structure
        output_dir = os.path.join(get_output_dir(), f"{domain}_{timestamp}")
        os.makedirs(output_dir, exist_ok=True)
        
        # Save broken links
        broken_filename = os.path.join(output_dir, "broken_links.csv")
        async with aiofiles.open(broken_filename, "w", encoding='utf-8') as file:
            await file.write("Broken Link,Source Page,Status Code,Error Category,Timestamp\n")
            for link in self.broken_links:
                await file.write(f"{link.url},{link.source_url},{link.status},{link.error_category.value if link.error_category else ''},{link.timestamp}\n")
        
        # Save all links
        all_links_filename = os.path.join(output_dir, "all_links.csv")
        async with aiofiles.open(all_links_filename, "w", encoding='utf-8') as file:
            await file.write("Link,Source Page,Status Code,Link Type,Depth,Is Orphaned,Timestamp\n")
            for link in self.all_links:
                await file.write(f"{link.url},{link.source_url},{link.status},{link.link_type.value},{link.depth},{link.is_orphaned},{link.timestamp}\n")
        
        console = Console()
        console.print(f"\n[green]Results saved to:[/green] {output_dir}")
        await self.analyze_results()

def display_banner():
    """Display the LinkGuardian banner and version information."""
    banner = """
██╗     ██╗███╗   ██╗██╗  ██╗     ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ██╗ █████╗ ███╗   ██╗
██║     ██║████╗  ██║██║ ██╔╝    ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗██║██╔══██╗████╗  ██║
██║     ██║██╔██╗ ██║█████╔╝     ██║  ███╗██║   ██║███████║██████╔╝██║  ██║██║███████║██╔██╗ ██║
██║     ██║██║╚██╗██║██╔═██╗     ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║██║██╔══██║██║╚██╗██║
███████╗██║██║ ╚████║██║  ██╗    ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝██║██║  ██║██║ ╚████║
╚══════╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝     ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝
    """
    
    info_text = Text()
    info_text.append("Version: 1.0.0\n", style="cyan")
    info_text.append("A powerful asynchronous website crawler and link checker\n", style="green")
    info_text.append("Built with ❤️ using Python\n", style="red")
    info_text.append("\nCreated by Farhan Ansari (https://github.com/fxrhan)\n", style="yellow")
    
    console = Console()
    console.print(Panel(banner, style="blue"))
    console.print(Panel(info_text, title="About", border_style="blue"))
    console.print("\n")

async def main():
    parser = argparse.ArgumentParser(description='LinkGuardian - Website Link Checker')
    parser.add_argument('--url', default="https://example.com", help='Base URL to crawl')
    parser.add_argument('--workers', type=int, default=10, help='Number of concurrent workers')
    parser.add_argument('--rate', type=float, default=0.5, help='Rate limit in seconds between requests')
    parser.add_argument('--max-pages', type=int, default=100, help='Maximum number of pages to crawl')
    parser.add_argument('--max-depth', type=int, default=3, help='Maximum crawl depth')
    parser.add_argument('--cache-dir', default=None, help='Directory for cache files')
    args = parser.parse_args()

    # Display banner
    display_banner()

    # Create necessary directories
    os.makedirs(get_cache_dir(), exist_ok=True)
    os.makedirs(get_output_dir(), exist_ok=True)

    # Start memory tracking
    tracemalloc.start()
    
    checker = LinkChecker(
        base_url=args.url,
        max_workers=args.workers,
        rate_limit=args.rate,
        max_pages=args.max_pages,
        max_depth=args.max_depth,
        cache_dir=args.cache_dir
    )
    
    console = Console()
    console.print(f"[cyan]Starting crawl of[/cyan] [bold blue]{args.url}[/bold blue]")
    console.print(f"[cyan]Max pages:[/cyan] {args.max_pages}, [cyan]Max depth:[/cyan] {args.max_depth}, "
                 f"[cyan]Workers:[/cyan] {args.workers}, [cyan]Rate limit:[/cyan] {args.rate}s")
    
    try:
        await checker.crawl_website()
        await checker.save_results()
    finally:
        if checker.session:
            await checker.session.close()
        
        # Print memory usage
        current, peak = tracemalloc.get_traced_memory()
        logger.info(f"Memory usage: {current / 10**6:.2f}MB")
        logger.info(f"Peak memory usage: {peak / 10**6:.2f}MB")
        tracemalloc.stop()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[red]Crawling interrupted by user[/red]")
        sys.exit(1)
    except Exception as e:
        print(f"\n[red]An error occurred: {str(e)}[/red]")
        sys.exit(1)
