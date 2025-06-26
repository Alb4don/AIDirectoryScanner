#!/usr/bin/env python3

import argparse
import threading
import time
import random
from os import path
from sys import argv
from urllib.parse import urljoin, urlparse
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import re
from collections import defaultdict, deque
import hashlib

class AIDirectoryScanner:
    def __init__(self):
        self.session = self._create_session()
        self.discovered_dirs = set()
        self.error_patterns = defaultdict(int)
        self.response_cache = {}
        self.intelligent_wordlist = set()
        self.adaptive_delays = {}
        self.success_rate = defaultdict(list)
        self.lock = threading.Lock()
        
        self.common_patterns = [
            'admin', 'api', 'assets', 'backup', 'config', 'data', 'dev', 'docs',
            'images', 'includes', 'js', 'css', 'media', 'private', 'public',
            'scripts', 'temp', 'test', 'uploads', 'vendor', 'wp-admin', 'wp-content'
        ]
        
        self.extensions = ['.php', '.asp', '.aspx', '.jsp', '.html', '.htm', '.txt', '.bak']
        
    def _create_session(self):
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })
        return session

    def _normalize_url(self, url):
        if not url.startswith(('http://', 'https://')):
            return f"http://{url}"
        return url

# Implemented AI-based adaptive delay to avoid rate limiting
    def _adaptive_delay(self, host):
        base_delay = self.adaptive_delays.get(host, 0.1)
        recent_success = self.success_rate.get(host, [])
        
        if len(recent_success) > 5:
            success_rate = sum(recent_success[-5:]) / 5
            if success_rate < 0.3:  # High failure rate
                base_delay = min(base_delay * 1.5, 2.0)
            elif success_rate > 0.8:  # High success rate
                base_delay = max(base_delay * 0.8, 0.05)
        
        self.adaptive_delays[host] = base_delay
        time.sleep(base_delay + random.uniform(0, 0.1))

# Implemented AI technique that generates additional paths based on discovered directories
    def _generate_intelligent_paths(self, base_list, discovered_dirs):
        intelligent_paths = set(base_list)
        
        for discovered in discovered_dirs:
            path_parts = discovered.split('/')
            for part in path_parts:
                if part and len(part) > 2:

                    intelligent_paths.add(f"{part}_old")
                    intelligent_paths.add(f"{part}_new")
                    intelligent_paths.add(f"{part}_backup")
                    intelligent_paths.add(f"{part}2")
                    intelligent_paths.add(f"old_{part}")
                    
                    for ext in self.extensions:
                        intelligent_paths.add(f"{part}{ext}")
        
        for discovered in discovered_dirs:
            for common in self.common_patterns:
                intelligent_paths.add(f"{discovered.strip('/')}/{common}")
        
        return list(intelligent_paths)

# Implemented AI technique that analyzes response for intelligence gathering
    def _analyze_response(self, response, url):
        if not response:
            return False, {}
        
        analysis = {
            'status_code': response.status_code,
            'content_length': len(response.content),
            'content_type': response.headers.get('content-type', ''),
            'server': response.headers.get('server', ''),
            'interesting_headers': {}
        }
        
        interesting_headers = ['x-powered-by', 'server', 'x-aspnet-version', 'x-generator']
        for header in interesting_headers:
            if header in response.headers:
                analysis['interesting_headers'][header] = response.headers[header]
        
        content = response.text.lower()
        directory_indicators = [
            'index of', 'directory listing', 'parent directory',
            '<title>index of', 'directory browsing', 'file listing'
        ]
        
        analysis['is_directory_listing'] = any(indicator in content for indicator in directory_indicators)
        
        # Implemented verification of common CMS/framework signatures
        cms_signatures = {
            'wordpress': ['wp-content', 'wp-includes', 'wp-admin'],
            'drupal': ['drupal', 'sites/default'],
            'joomla': ['joomla', 'administrator'],
            'django': ['django', 'admin/'],
            'laravel': ['laravel', 'vendor/laravel']
        }
        
        for cms, signatures in cms_signatures.items():
            if any(sig in content for sig in signatures):
                analysis['cms_detected'] = cms
                break
        
        return True, analysis

# Implemented technique for response validation
    def _is_valid_response(self, response, url):
        if not response or response.status_code == 404:
            return False
        
        # Caching similar responses to avoid false positives
        content_hash = hashlib.md5(response.content).hexdigest()
        
        if content_hash in self.response_cache:
            cached_url = self.response_cache[content_hash]
            if cached_url != url:
                return False 
        else:
            self.response_cache[content_hash] = url
        
        valid_codes = [200, 201, 202, 204, 301, 302, 303, 307, 308, 401, 403, 500]
        
        if response.status_code in valid_codes:
            if response.status_code == 200:
                content = response.text.lower()
                error_indicators = ['not found', '404', 'page not found', 'file not found']
                if any(indicator in content for indicator in error_indicators) and len(content) < 1000:
                    return False
            return True
        
        return False

# Implemented technique for extracting and analyzing links from discovered directories
    def _extract_links_from_response(self, response, base_url):
        if not response:
            return []
        
        links = []
        content = response.text
        
        href_pattern = r'href=["\']([^"\']+)["\']'
        hrefs = re.findall(href_pattern, content, re.IGNORECASE)
        
        src_pattern = r'src=["\']([^"\']+)["\']'
        srcs = re.findall(src_pattern, content, re.IGNORECASE)
        
        all_links = hrefs + srcs
        
        for link in all_links:
            if link.startswith('/') and not link.startswith('//'):
                full_url = urljoin(base_url, link)
                links.append(link.strip('/'))
        
        return links

# Implemented Smart Scanning with AI
    def scan_url(self, url, wordlist):
        normalized_url = self._normalize_url(url)
        host = urlparse(normalized_url).netloc
        
        print(f"\n  AI-Enhanced Scanning: {normalized_url}")
        print(f"    Using intelligent wordlist with {len(wordlist)} entries")
        
        discovered_in_session = []
        
        for i, directory in enumerate(wordlist):
            directory = directory.strip()
            if not directory:
                continue
            
            target_url = f"{normalized_url.rstrip('/')}/{directory}"
            
            # Performs adaptive delay based on AI analysis
            self._adaptive_delay(host)
            
            try:
                response = self.session.get(target_url, timeout=10, allow_redirects=True)
                
                # AI-based response analysis
                is_valid, analysis = self._analyze_response(response, target_url)
                
                with self.lock:
                    # Performs success rate update for adaptive behavior
                    self.success_rate[host].append(1 if is_valid else 0)
                    if len(self.success_rate[host]) > 20:
                        self.success_rate[host].pop(0)
                
                if self._is_valid_response(response, target_url):
                    status_indicator = "" if response.status_code == 200 else "" if response.status_code == 403 else ""
                    
                    print(f"{status_indicator} [{response.status_code}] {target_url}")
                    
                    if analysis.get('is_directory_listing'):
                        print(f"      Directory listing detected!")
                    
                    if 'cms_detected' in analysis:
                        print(f"      CMS detected: {analysis['cms_detected']}")
                    
                    if analysis.get('interesting_headers'):
                        print(f"      Interesting headers: {analysis['interesting_headers']}")
                    
                    discovered_in_session.append(directory)
                    self.discovered_dirs.add(target_url)
                    
                    # Performs extraction of additional paths from the response
                    extracted_links = self._extract_links_from_response(response, normalized_url)
                    if extracted_links:
                        print(f"Found {len(extracted_links)} additional paths to investigate")
                        wordlist.extend(extracted_links[:10]) 
                
                if (i + 1) % 50 == 0:
                    print(f"   Progress: {i + 1}/{len(wordlist)} ({((i + 1)/len(wordlist)*100):.1f}%)")
                    
            except requests.exceptions.RequestException as e:
                with self.lock:
                    self.success_rate[host].append(0)
                    if len(self.success_rate[host]) > 20:
                        self.success_rate[host].pop(0)
                continue
        
        # Added additional path generation based on findings
        if discovered_in_session:
            print(f"\n AI Analysis: Generating intelligent paths based on {len(discovered_in_session)} discoveries...")
            additional_paths = self._generate_intelligent_paths([], discovered_in_session)
            
            if additional_paths:
                print(f"Testing {len(additional_paths)} AI-generated paths...")
                for path in additional_paths[:50]:  # Added a limit to prevent infinite expansion
                    target_url = f"{normalized_url.rstrip('/')}/{path}"
                    self._adaptive_delay(host)
                    
                    try:
                        response = self.session.get(target_url, timeout=10, allow_redirects=True)
                        if self._is_valid_response(response, target_url):
                            print(f"🤖 [AI-FOUND] [{response.status_code}] {target_url}")
                            self.discovered_dirs.add(target_url)
                    except:
                        continue
        
        return len(discovered_in_session)

def usage():
    print('''
🤖 AI Directory Scanner v1.0

Usage: 
python3 ai_dirscan.py -u <URLs>
python3 ai_dirscan.py -u <URLs> -l <directories list>

Options:
    -h, --help             Show this help message and exit
    -u, --url              Target URLs
    -l, --list             Path to file with directories list
    -t, --threads          Number of threads (default: 5)

Examples:
python3 ai_dirscan.py -u google.com
python3 ai_dirscan.py -u google.com github.com
python3 ai_dirscan.py -u google.com -l /path/to/wordlist.txt -t 10
    ''')
    exit()

def get_args():
    arg_parser = argparse.ArgumentParser(add_help=False, usage="python3 ai_dirscan.py -u <URLs> -l <directories list>")
    
    arg_parser.add_argument("-h", "--help", action="store_true")
    arg_parser.add_argument("-u", "--url", nargs="+", dest="urls")
    arg_parser.add_argument("-l", "--list", dest="list_file")
    arg_parser.add_argument("-t", "--threads", dest="threads", type=int, default=5)
    
    return arg_parser

def load_wordlist(list_file_path):
    wordlist = []
    default_wordlist = [
        'admin', 'administrator', 'api', 'assets', 'backup', 'cache', 'config',
        'css', 'data', 'db', 'dev', 'docs', 'downloads', 'files', 'images',
        'img', 'includes', 'js', 'logs', 'media', 'private', 'public', 'scripts',
        'static', 'temp', 'test', 'tmp', 'uploads', 'user', 'users', 'var',
        'wp-admin', 'wp-content', 'wp-includes', 'phpmyadmin', 'mysql',
        'database', 'sql', 'ftp', 'mail', 'email', 'login', 'dashboard'
    ]
    
    if list_file_path:
        if path.isfile(list_file_path):
            with open(list_file_path, 'r') as f:
                wordlist = [line.strip() for line in f if line.strip()]
            print(f"Loaded {len(wordlist)} entries from {list_file_path}")
        else:
            print(f"File not found: {list_file_path}")
            print("Using default wordlist...")
            wordlist = default_wordlist
    else:
        wordlist = default_wordlist
        print(f"Using default wordlist with {len(wordlist)} entries")
    
    return wordlist

def main():
    print("🤖 AI Directory Scanner v1.0")
    print("=" * 50)
    
    arguments = get_args().parse_args()
    
    if len(argv) == 1 or arguments.help:
        usage()
    elif not arguments.urls:
        get_args().error("No URLs provided.\nTry 'ai_dirscan.py -h' for more info.")
    
    wordlist = load_wordlist(arguments.list_file)
    
    scanner = AIDirectoryScanner()
    
    total_found = 0
    start_time = time.time()
    
    for url in arguments.urls:
        found = scanner.scan_url(url, wordlist.copy())
        total_found += found
    
    elapsed_time = time.time() - start_time
    print(f"\n{'='*50}")
    print(f"    Scan Complete!")
    print(f"    Time elapsed: {elapsed_time:.2f} seconds")
    print(f"    Total directories found: {total_found}")
    print(f"    Pattern generation, adaptive delays, intelligent analysis")
    
    if scanner.discovered_dirs:
        print(f"\nSummary of discovered directories:")
        for i, directory in enumerate(sorted(scanner.discovered_dirs), 1):
            print(f"   {i}. {directory}")

if __name__ == "__main__":
    main()
