import requests
from bs4 import BeautifulSoup
import time
import argparse
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import tldextract
import os
import urllib3
import re

# 抑制不安全的 SSL 警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def is_valid_url(url):
    """验证URL是否为有效的链接"""
    # 使用正则表达式检查 URL 格式，并过滤掉无效的链接
    pattern = re.compile(
        r'^(https?://)?'  # 支持 http 或 https 协议
        r'(([A-Za-z0-9-]+\.)+[A-Za-z]{2,6})'  # 域名部分
    )
    return bool(pattern.match(url))

def extract_links(url):
    """提取給定頁面中的所有連結，包含重試機制並忽略 SSL 驗證錯誤"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36'
    }
    
    # 設置 Session 和重試策略
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=0.3, status_forcelist=[500, 502, 503, 504])
    session.mount('https://', HTTPAdapter(max_retries=retries))
    
    try:
        # 忽略 SSL 驗證錯誤，並設置超時
        response = session.get(url, headers=headers, verify=False, timeout=10)
        response.raise_for_status()  # 確保請求成功
        soup = BeautifulSoup(response.text, 'html.parser')

        # 提取所有 a 標籤中的 href 屬性值
        links = set()
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            # 使用 urljoin 來處理相對和絕對路徑
            full_url = urljoin(url, href)
            links.add(full_url)

        return links

    except requests.exceptions.RequestException as e:
        print(f"An error occurred while fetching {url}: {e}")
        return set()

def extract_domain(link):
    """從URL中提取根域名部分"""
    extracted = tldextract.extract(link)
    return f"{extracted.domain}.{extracted.suffix}"

def should_filter_domain(domain, filter_domains):
    """檢查根域名是否在過濾清單中"""
    return domain in filter_domains

def process_url(url, stored_domains, output_file, delay, filter_domains):
    """處理單個URL：爬取連結並保存域名"""
    print(f"Crawling: {url}")
    links = extract_links(url)

    # 提取並儲存根域名部分，避免重複
    for link in links:
        # 验证链接格式是否有效
        if not is_valid_url(link):
            print(f"Invalid URL skipped: {link}")
            continue
        
        root_domain = extract_domain(link)
        # 檢查根域名是否在過濾清單中
        if root_domain and root_domain not in stored_domains and not should_filter_domain(root_domain, filter_domains):
            with open(output_file, 'a', encoding='utf-8') as f:
                f.write(root_domain + '\n')
            stored_domains.add(root_domain)
    
    time.sleep(delay)  # 延遲，避免過快爬取被網站封鎖
    return links

def crawl(start_urls, output_file, delay=1, max_threads=5, filter_domains=None):
    """無限爬取網站中的連結並即時存檔"""
    to_crawl = set(start_urls)  # 使用集合來避免重複
    crawled = set()  # 紀錄已爬取的連結
    stored_domains = set()  # 已存儲的域名，避免重複存儲

    if filter_domains is None:
        filter_domains = []

    # 檢查文件路径是否可写
    output_dir = os.path.dirname(output_file) or '.'
    if not os.access(output_dir, os.W_OK):
        print(f"Output directory is not writable: {output_dir}")
        return

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        while to_crawl:  # 當有待爬取的連結時繼續爬取
            print(f"Crawling {len(to_crawl)} URLs...")
            next_to_crawl = set()

            # 提交多執行緒任務
            futures = {executor.submit(process_url, url, stored_domains, output_file, delay, filter_domains): url for url in to_crawl if url not in crawled}

            for future in as_completed(futures):
                url = futures[future]
                crawled.add(url)  # 標記為已爬取
                try:
                    links = future.result()  # 獲取該 URL 的子連結
                    next_to_crawl.update(links)  # 添加新獲得的連結
                except Exception as e:
                    print(f"Error while crawling {url}: {e}")

            # 將下一輪爬取的連結更新為當前集合中未爬取的部分
            to_crawl = next_to_crawl - crawled

            # 控制爬取速度，避免過快發送請求
            if delay > 0:
                time.sleep(delay)

def generate_unique_filename(base_name):
    """產生唯一的檔案名稱，根據當前時間"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    return f"{base_name}_{timestamp}.txt"

def add_scheme(url):
    """為URL添加默認協議，如果沒有"""
    if not url.startswith('http://') and not url.startswith('https://'):
        return 'https://' + url
    return url

def load_filter_domains(file_path):
    """從文件中加載過濾清單"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Filter file not found: {file_path}")
        return []

def main():
    # 使用 argparse 解析命令行參數
    parser = argparse.ArgumentParser(description="無限爬取網站連結的簡單爬蟲工具")
    parser.add_argument('--start_url', type=str, help='起始爬取的網站URL')
    parser.add_argument('--input_file', type=str, help='包含起始網站URL的檔案，每行一個URL')
    parser.add_argument('--base_output_file', type=str, default='crawled_domains', help='儲存域名的檔案名稱基底 (預設: crawled_domains)')
    parser.add_argument('--delay', type=int, default=1, help='每次爬取之間的延遲時間，避免爬取過快 (預設: 1秒)')
    parser.add_argument('--max_threads', type=int, default=5, help='最多使用的線程數量 (預設: 5)')
    parser.add_argument('--filter_file', type=str, help='指定包含要過濾的根域名清單的檔案')

    args = parser.parse_args()

    # 確認至少有一個起始URL輸入
    start_urls = []
    if args.input_file:
        try:
            with open(args.input_file, 'r', encoding='utf-8') as f:
                start_urls = [add_scheme(line.strip()) for line in f if line.strip()]
        except FileNotFoundError:
            print(f"File not found: {args.input_file}")
            return
    elif args.start_url:
        start_urls.append(add_scheme(args.start_url))
    else:
        print("請提供起始爬取的網站URL或包含入口網站的檔案")
        return

    # 加載過濾清單
    filter_domains = load_filter_domains(args.filter_file) if args.filter_file else []

    # 生成唯一的檔案名稱
    output_file = generate_unique_filename(args.base_output_file)

    # 執行爬蟲，加入過濾根域名清單
    crawl(start_urls, output_file, args.delay, args.max_threads, filter_domains)

if __name__ == '__main__':
    main()



