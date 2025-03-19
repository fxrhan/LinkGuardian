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
import stat

# Initialize colorama for Windows support
init()

# Get the user's home directory in a cross-platform way
HOME_DIR = str(pathlib.Path.home())
APP_NAME = "LinkGuardian"
APP_DIR = os.path.join(HOME_DIR, f".{APP_NAME.lower()}")

def ensure_directory_permissions(directory: str):
    """Ensure directory has correct permissions across platforms."""
    try:
        if platform.system() != 'Windows':
            # Set read/write permissions for user on Unix-like systems
            os.chmod(directory, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
    except Exception as e:
        logger.warning(f"Could not set directory permissions: {e}")

# Configure logging with more detail
def setup_logging():
    """Setup logging with platform-specific paths."""
    log_dir = os.path.join(APP_DIR, "logs")
    os.makedirs(log_dir, exist_ok=True)
    ensure_directory_permissions(log_dir)
    
    log_file = os.path.join(log_dir, "linkchecker.log")
    
    # Ensure log file has correct permissions
    if os.path.exists(log_file):
        ensure_directory_permissions(log_file)
    
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
    ensure_directory_permissions(cache_dir)
    return cache_dir

def get_output_dir() -> str:
    """Get the output directory path based on the operating system."""
    output_dir = os.path.join(APP_DIR, "output")
    os.makedirs(output_dir, exist_ok=True)
    ensure_directory_permissions(output_dir)
    return output_dir

def get_platform_user_agent() -> str:
    """Get platform-specific user agent string."""
    system = platform.system()
    if system == 'Windows':
        return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    elif system == 'Darwin':  # macOS
        return "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    else:  # Linux and others
        return "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

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

    def to_dict(self):
        """Convert LinkInfo to a dictionary for JSON serialization."""
        result = {
            "url": self.url,
            "source_url": self.source_url,
            "status": self.status,
            "link_type": self.link_type.value if self.link_type else None,
            "depth": self.depth,
            "is_orphaned": self.is_orphaned,
            "timestamp": self.timestamp
        }
        if self.error_category:
            result["error_category"] = self.error_category.value
        return result

class LinkChecker:
    def __init__(
        self,
        base_url: str,
        max_workers: int = 10,
        rate_limit: float = 0.5,
        max_pages: int = 100,
        max_depth: int = 3,
        cache_dir: Optional[str] = None,
        ignore_robots: bool = False
    ):
        self.base_url = base_url
        self.max_workers = max_workers
        self.rate_limit = rate_limit
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.cache_dir = cache_dir or get_cache_dir()
        self.ignore_robots = ignore_robots
        self.robots_parser = None
        self.session = None
        self.ssl_context = ssl.create_default_context(cafile=certifi.where())
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        self.visited_urls: Set[str] = set()
        self.url_queue: deque = deque([(base_url, 0)])
        self.broken_links: List[LinkInfo] = []
        self.all_links: List[LinkInfo] = []
        self.orphaned_pages: Set[str] = set()
        self.redirect_chains: Dict[str, List[str]] = {}
        self.duplicate_content: Dict[str, List[str]] = {}
        self.console = Console()
        self.progress = None
        self.crawl_task = None
        self.start_time = None
        self.end_time = None
        self.initial_memory = None
        self.peak_memory = None
        self.ssl_errors = 0
        self.timeout_errors = 0
        self.connection_errors = 0
        self.http_errors = 0
        self.parsing_errors = 0
        self.validation_errors = 0
        self.unknown_errors = 0
        self.retry_count = 0
        self.max_retries = 3
        self.retry_delay = 1
        self.rate_limit_semaphore = asyncio.Semaphore(1)
        self.robots_parser = None
        self.robots_checked = False

    async def crawl(self):
        """Start the crawling process."""
        self.start_time = time.time()
        self.initial_memory = tracemalloc.get_traced_memory()[0]
        tracemalloc.start()
        
        # Create session
        await self._create_session()
        
        # Load cache if exists
        await self._load_cache()
        
        # Create progress bar
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TextColumn("[bold]{task.fields[status]}"),
            expand=True
        )
        
        with self.progress:
            self.crawl_task = self.progress.add_task("[cyan]Crawling...", total=self.max_pages, status="Starting")
            
            # Create worker tasks
            tasks = []
            for _ in range(self.max_workers):
                tasks.append(asyncio.create_task(self._worker()))
            
            # Wait for all workers to complete
            await asyncio.gather(*tasks)
            
            # Save cache
            await self._save_cache()
            
            # Save results
            await self.save_results()
        
        self.end_time = time.time()
        self.peak_memory = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
        
        # Close session
        if self.session:
            await self.session.close()

    async def _worker(self):
        """Worker that processes URLs from the queue."""
        while self.url_queue and len(self.visited_urls) < self.max_pages:
            # Get URL from queue
            url, depth = self.url_queue.popleft()
            
            # Skip if already visited
            if url in self.visited_urls:
                continue
            
            # Skip if depth exceeds max_depth
            if depth > self.max_depth:
                continue
            
            # Check robots.txt
            if not await self._check_robots_txt(url):
                continue
            
            # Process URL
            await self._process_url(url, depth)
            
            # Rate limiting
            await self._rate_limit()
            
            # Update progress
            self.progress.update(self.crawl_task, completed=len(self.visited_urls), status=f"Visited: {len(self.visited_urls)}, Queue: {len(self.url_queue)}, Broken: {len(self.broken_links)}")
        
        # If no more URLs in queue or max pages reached
        if not self.url_queue or len(self.visited_urls) >= self.max_pages:
            self.progress.update(self.crawl_task, completed=self.max_pages, status="Completed")

    async def _process_url(self, url: str, depth: int):
        """Process a URL by fetching it and extracting links."""
        # Mark as visited
        self.visited_urls.add(url)
        
        try:
            # Fetch URL
            async with self.session.get(url, allow_redirects=True) as response:
                # Handle redirects
                if response.history:
                    redirect_chain = [str(resp.url) for resp in response.history] + [str(response.url)]
                    self.redirect_chains[url] = redirect_chain
                
                # Get content and parse links
                content = await response.text()
                
                # Create link info
                link_info = LinkInfo(
                    url=url,
                    source_url=url,
                    status=response.status,
                    link_type=LinkType.INTERNAL if urlparse(url).netloc == urlparse(self.base_url).netloc else LinkType.EXTERNAL,
                    depth=depth,
                    is_orphaned=False,
                    timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                )
                
                self.all_links.append(link_info)
                
                # If not OK status, add to broken links
                if response.status >= 400:
                    link_info.error_category = ErrorCategory.HTTP_ERROR
                    self.broken_links.append(link_info)
                    self.http_errors += 1
                    return
                
                # Parse links if HTML
                content_type = response.headers.get("Content-Type", "")
                if "text/html" in content_type:
                    new_links = await self._extract_links(url, content, depth + 1)
                    
                    # Add new links to queue
                    for new_link in new_links:
                        if new_link not in self.visited_urls and new_link not in [url for url, _ in self.url_queue]:
                            self.url_queue.append((new_link, depth + 1))
        
        except aiohttp.ClientConnectorError as e:
            self._handle_error(url, ErrorCategory.CONNECTION_ERROR, str(e), depth)
            self.connection_errors += 1
        except aiohttp.ServerTimeoutError as e:
            self._handle_error(url, ErrorCategory.TIMEOUT_ERROR, str(e), depth)
            self.timeout_errors += 1
        except aiohttp.ClientSSLError as e:
            self._handle_error(url, ErrorCategory.SSL_ERROR, str(e), depth)
            self.ssl_errors += 1
        except aiohttp.ClientError as e:
            self._handle_error(url, ErrorCategory.HTTP_ERROR, str(e), depth)
            self.http_errors += 1
        except Exception as e:
            self._handle_error(url, ErrorCategory.UNKNOWN_ERROR, str(e), depth)
            self.unknown_errors += 1
            logger.exception(f"Error processing URL {url}: {str(e)}")

    def _handle_error(self, url: str, error_category: ErrorCategory, error_message: str, depth: int):
        """Handle and log an error for a URL."""
        link_info = LinkInfo(
            url=url,
            source_url=self.base_url,  # Default to base URL as we don't know the source
            status=0,  # 0 means we couldn't get a status
            link_type=LinkType.INTERNAL if urlparse(url).netloc == urlparse(self.base_url).netloc else LinkType.EXTERNAL,
            depth=depth,
            is_orphaned=False,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            error_category=error_category
        )
        
        self.broken_links.append(link_info)
        self.all_links.append(link_info)
        logger.error(f"Error fetching {url}: {error_message}")

    async def _extract_links(self, source_url: str, html_content: str, depth: int) -> List[str]:
        """Extract links from HTML content."""
        try:
            soup = BeautifulSoup(html_content, "html.parser")
            links = []
            
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"]
                try:
                    # Skip if empty, javascript, mailto, tel, etc.
                    if not href or href.startswith(("javascript:", "mailto:", "tel:", "#")):
                        continue
                    
                    # Resolve relative URLs
                    absolute_url = urljoin(source_url, href)
                    
                    # Skip if different domain and not checking external links
                    if urlparse(absolute_url).netloc != urlparse(self.base_url).netloc:
                        # Add to all_links but don't crawl
                        link_info = LinkInfo(
                            url=absolute_url,
                            source_url=source_url,
                            status=0,  # We haven't checked it yet
                            link_type=LinkType.EXTERNAL,
                            depth=depth,
                            is_orphaned=False,
                            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        )
                        self.all_links.append(link_info)
                        
                        # Only include in links to crawl if same domain
                        continue
                    
                    # Clean URL (remove fragments)
                    parsed = urlparse(absolute_url)
                    clean_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, parsed.query, ""))
                    
                    links.append(clean_url)
                    
                    # Add to all_links
                    link_info = LinkInfo(
                        url=clean_url,
                        source_url=source_url,
                        status=0,  # We haven't checked it yet
                        link_type=LinkType.INTERNAL,
                        depth=depth,
                        is_orphaned=False,
                        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    )
                    self.all_links.append(link_info)
                
                except Exception as e:
                    logger.warning(f"Error processing link {href}: {str(e)}")
                    self.parsing_errors += 1
            
            return list(set(links))  # Remove duplicates
        
        except Exception as e:
            logger.error(f"Error extracting links from {source_url}: {str(e)}")
            self.parsing_errors += 1
            return []

    async def _rate_limit(self):
        """Implement rate limiting."""
        async with self.rate_limit_semaphore:
            await asyncio.sleep(self.rate_limit)

    async def _create_session(self):
        """Create an aiohttp session with SSL context."""
        if not self.session:
            self.session = aiohttp.ClientSession(
                headers={
                    "User-Agent": get_platform_user_agent()
                },
                timeout=aiohttp.ClientTimeout(total=30),
                connector=aiohttp.TCPConnector(ssl=self.ssl_context)
            )

    async def _check_robots_txt(self, url: str) -> bool:
        """Check if URL is allowed by robots.txt."""
        if hasattr(self, 'ignore_robots') and self.ignore_robots:
            return True
            
        if not self.robots_checked:
            try:
                robots_url = urljoin(url, "/robots.txt")
                async with self.session.get(robots_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        self.robots_parser = RobotFileParser()
                        self.robots_parser.parse(content.splitlines())
                        self.robots_checked = True
                    else:
                        self.robots_checked = True
                        return True
            except Exception as e:
                logger.warning(f"Error checking robots.txt: {e}")
                self.robots_checked = True
                return True

        if self.robots_parser:
            return self.robots_parser.can_fetch(get_platform_user_agent(), url)
        return True

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
                if not await self._check_robots_txt(current_url):
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
        """Analyze the results and print a summary."""
        console = Console()
        console.print("\n[bold]Analysis Results:[/bold]")
        
        # Count various types of links
        working_links = [link for link in self.all_links if link.status < 400 and link.status > 0]
        broken_links = self.broken_links
        internal_links = [link for link in self.all_links if link.link_type == LinkType.INTERNAL]
        external_links = [link for link in self.all_links if link.link_type == LinkType.EXTERNAL]
        orphaned_pages = [link for link in self.all_links if link.is_orphaned]
        
        # Print summary
        console.print(f"[green]Total pages:[/green] {len(self.visited_urls)}")
        console.print(f"[green]Total links:[/green] {len(self.all_links)}")
        console.print(f"[green]Working links:[/green] {len(working_links)}")
        console.print(f"[red]Broken links:[/red] {len(broken_links)}")
        console.print(f"[blue]Internal links:[/blue] {len(internal_links)}")
        console.print(f"[yellow]External links:[/yellow] {len(external_links)}")
        console.print(f"[red]Orphaned pages:[/red] {len(orphaned_pages)}")
        
        # Print performance metrics
        elapsed_time = self.end_time - self.start_time if self.end_time and self.start_time else 0
        memory_usage = (self.peak_memory - self.initial_memory) / 1024 / 1024 if self.peak_memory and self.initial_memory else 0
        console.print(f"[cyan]Crawl time:[/cyan] {elapsed_time:.2f} seconds")
        console.print(f"[cyan]Memory usage:[/cyan] {memory_usage:.2f} MB")
        
        # Print error counts
        console.print("\n[bold]Error Counts:[/bold]")
        console.print(f"[red]SSL Errors:[/red] {self.ssl_errors}")
        console.print(f"[red]Timeout Errors:[/red] {self.timeout_errors}")
        console.print(f"[red]Connection Errors:[/red] {self.connection_errors}")
        console.print(f"[red]HTTP Errors:[/red] {self.http_errors}")
        console.print(f"[red]Parsing Errors:[/red] {self.parsing_errors}")
        console.print(f"[red]Unknown Errors:[/red] {self.unknown_errors}")

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

    async def _save_cache(self):
        """Save the current state to a cache file."""
        try:
            # Create cache directory if it doesn't exist
            cache_dir = self.cache_dir
            os.makedirs(cache_dir, exist_ok=True)
            
            # Create a cache file name based on the domain
            domain = urlparse(self.base_url).netloc.replace(".", "_")
            cache_file = os.path.join(cache_dir, f"{domain}_cache.json")
            
            # Convert data to JSON-serializable format
            all_links_data = []
            for link in self.all_links:
                link_dict = link.to_dict()
                all_links_data.append(link_dict)
                
            data = {
                "visited_urls": list(self.visited_urls),
                "all_links": all_links_data,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
            # Save to file
            async with aiofiles.open(cache_file, "w", encoding='utf-8') as f:
                await f.write(json.dumps(data, indent=2))
                
            logger.info(f"Cache saved to {cache_file}")
            
        except Exception as e:
            logger.error(f"Error saving cache: {str(e)}")

    async def _load_cache(self):
        """Load the state from a cache file if it exists."""
        try:
            # Get cache file path
            domain = urlparse(self.base_url).netloc.replace(".", "_")
            cache_file = os.path.join(self.cache_dir, f"{domain}_cache.json")
            
            # Check if cache file exists
            if not os.path.exists(cache_file):
                logger.info("No cache file found")
                return
            
            # Load data from file
            async with aiofiles.open(cache_file, "r", encoding='utf-8') as f:
                content = await f.read()
                data = json.loads(content)
            
            # Restore state
            self.visited_urls = set(data.get("visited_urls", []))
            
            # Restore all_links
            all_links_data = data.get("all_links", [])
            for link_data in all_links_data:
                # Convert string values back to enum types
                link_type_str = link_data.get("link_type")
                error_category_str = link_data.get("error_category")
                
                link_type = None
                if link_type_str:
                    try:
                        link_type = LinkType(link_type_str)
                    except ValueError:
                        link_type = LinkType.INTERNAL
                
                error_category = None
                if error_category_str:
                    try:
                        error_category = ErrorCategory(error_category_str)
                    except ValueError:
                        error_category = ErrorCategory.UNKNOWN_ERROR
                
                link_info = LinkInfo(
                    url=link_data.get("url", ""),
                    source_url=link_data.get("source_url", ""),
                    status=link_data.get("status", 0),
                    link_type=link_type or LinkType.INTERNAL,
                    depth=link_data.get("depth", 0),
                    is_orphaned=link_data.get("is_orphaned", False),
                    timestamp=link_data.get("timestamp", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                    error_category=error_category
                )
                
                self.all_links.append(link_info)
                
                # Add to broken_links if it has an error category
                if error_category:
                    self.broken_links.append(link_info)
            
            logger.info(f"Loaded {len(self.visited_urls)} visited URLs and {len(self.all_links)} links from cache")
            
        except Exception as e:
            logger.error(f"Error loading cache: {str(e)}")
            # Continue without cache

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

def main():
    parser = argparse.ArgumentParser(description="Crawl a website and check for broken links")
    parser.add_argument("--url", default="https://example.com", help="Base URL to crawl")
    parser.add_argument("--workers", type=int, default=10, help="Number of concurrent workers")
    parser.add_argument("--rate", type=float, default=0.5, help="Rate limit in seconds between requests")
    parser.add_argument("--max-pages", type=int, default=100, help="Maximum number of pages to crawl")
    parser.add_argument("--max-depth", type=int, default=3, help="Maximum crawl depth")
    parser.add_argument("--cache-dir", help="Custom directory for cache files")
    parser.add_argument("--ignore-robots", action="store_true", help="Ignore robots.txt rules")
    args = parser.parse_args()

    # Create output directory if it doesn't exist
    output_dir = get_output_dir()
    os.makedirs(output_dir, exist_ok=True)
    ensure_directory_permissions(output_dir)

    # Display banner with creator info
    display_banner()
    
    # Create console for rich output
    console = Console()
    console.print(f"\n[cyan]Starting crawl of:[/cyan] {args.url}")
    if args.ignore_robots:
        console.print("[yellow]Warning: robots.txt rules will be ignored[/yellow]")
    
    # Create and run the crawler
    crawler = LinkChecker(
        args.url,
        max_workers=args.workers,
        rate_limit=args.rate,
        max_pages=args.max_pages,
        max_depth=args.max_depth,
        cache_dir=args.cache_dir,
        ignore_robots=args.ignore_robots
    )
    
    # Helper function to run the crawler
    async def run_crawler():
        try:
            await crawler.crawl()
        except KeyboardInterrupt:
            console.print("\n[yellow]Crawling interrupted by user. Saving progress...[/yellow]")
            await crawler.save_results()
        except Exception as e:
            console.print(f"\n[red]An error occurred:[/red] {str(e)}")
            logger.error(f"Error during crawl: {str(e)}", exc_info=True)
            await crawler.save_results()
    
    # Check if we're in a running event loop
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # If already running, create a new task
            asyncio.create_task(run_crawler())
        else:
            # If not running, run the crawler
            loop.run_until_complete(run_crawler())
    except RuntimeError:
        # If no event loop exists, create one
        asyncio.run(run_crawler())

if __name__ == "__main__":
    main()
