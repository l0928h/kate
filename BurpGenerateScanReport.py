import requests
import json
import os
from rich.console import Console
from rich.table import Table
import logging
from datetime import datetime

# 配置 Burp Suite REST API 的 URL
burp_url = "http://127.0.0.1:1337/v0.1"  # 使用 v0.1 版本

# 设置 HTTP 头信息
headers = {
    "Content-Type": "application/json"
}

console = Console()

# 设置日志配置，将日志输出到文件
logging.basicConfig(level=logging.DEBUG, format='[%(asctime)s] [%(levelname)s] %(message)s', datefmt='%H:%M:%S', filename='burp_scan_status.log', filemode='w')
logger = logging.getLogger()

# 创建保存结果的目录
results_dir = "results/burp"
os.makedirs(results_dir, exist_ok=True)

# 创建保存扫描 ID 的文件
scan_ids_file = "scan_ids.json"

# 获取当前时间的函数
def current_time():
    return datetime.now().strftime('%H:%M:%S')

# 获取单个扫描任务的详细信息并显示所有事件
def get_scan_details(scan_id):
    high_risk_count = 0
    url = "N/A"
    status = "unknown"
    try:
        response = requests.get(f"{burp_url}/scan/{scan_id}", headers=headers)
        logger.debug(f"HTTP Response Status Code: {response.status_code}")
        logger.debug(f"HTTP Response Content: {response.text}")
        if response.status_code == 200:
            data = response.json()
            status = data.get('scan_metrics', {}).get('crawl_and_audit_caption', 'unknown')
            progress = data.get('scan_metrics', {}).get('crawl_and_audit_progress', 0)
            issues = data.get('issue_events', [])
            if issues:
                url = issues[0]['issue'].get('origin', 'N/A')
                # 保存 JSON 数据到文件
                if progress == 100:  # 确认扫描任务完成
                    url_filename = os.path.join(results_dir, url.replace("://", "_").replace("/", "_") + ".json")
                    with open(url_filename, "w", encoding='utf-8') as f:
                        json.dump(data, f, ensure_ascii=False, indent=4)
                
                table = Table(title=f"所有事件 (扫描 ID: {scan_id}, URL: {url})")
                table.add_column("Issue Name", style="cyan", no_wrap=True)
                table.add_column("Severity", style="magenta")
                table.add_column("Confidence", style="green")
                table.add_column("URL", style="blue")

                for item in issues:
                    issue = item['issue']
                    if issue.get("severity") == "high":
                        high_risk_count += 1
                    table.add_row(
                        issue.get("name", "N/A"),
                        issue.get("severity", "N/A"),
                        issue.get("confidence", "N/A"),
                        issue.get("path", "N/A"),
                    )

                console.print(table)
            console.print(f"[{current_time()}] [INFO] 扫描 ID: {scan_id}，URL: {url}，状态: {status}，进度: {progress}%")
        else:
            logger.error(f"获取扫描结果失败，扫描 ID: {scan_id}，状态码: {response.status_code}, 错误信息: {response.text}")
            console.print(f"[{current_time()}] [ERROR] 获取扫描结果失败，扫描 ID: {scan_id}，状态码: {response.status_code}，错误信息: {response.text}")
    except Exception as e:
        logger.error(f"发生错误: {e}")
        console.print(f"[{current_time()}] [ERROR] 发生错误: {e}")
    return high_risk_count, url, status

# 从 scan_ids.json 文件中加载扫描 ID
def load_scan_ids():
    try:
        with open(scan_ids_file, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        console.print(f"[red]未找到 {scan_ids_file} 文件。请先创建扫描任务。[/red]")
        return []

def display_all_scans():
    scan_ids = load_scan_ids()
    total_high_risk_count = 0
    scan_info = []

    for scan_id in scan_ids:
        high_risk_count, url, status = get_scan_details(scan_id)
        total_high_risk_count += high_risk_count
        scan_info.append((scan_id, url, high_risk_count, status))

    console.print(f"\n总共发现 {total_high_risk_count} 个高风险事件。")

    summary_table = Table(title="各扫描任务的高风险事件统计")
    summary_table.add_column("Scan ID", style="cyan", no_wrap=True)
    summary_table.add_column("URL", style="blue")
    summary_table.add_column("High Risk Issues", style="red")
    summary_table.add_column("Status", style="green")

    for scan_id, url, count, status in scan_info:
        summary_table.add_row(str(scan_id), url, str(count), status)

    console.print(summary_table)

def main_menu():
    while True:
        console.print("\n请选择一个选项:")
        console.print("1. 读取单个扫描任务的数据")
        console.print("2. 列出所有扫描任务的数据")
        console.print("3. 退出")

        choice = input("请输入你的选择: ").strip()
        
        if choice == "1":
            scan_id = input("请输入扫描任务 ID: ").strip()
            get_scan_details(scan_id)
        elif choice == "2":
            display_all_scans()
        elif choice == "3":
            console.print("[bold magenta]感谢使用 BurpAutoPilot! 再见![/bold magenta]")
            break
        else:
            console.print("[red]无效的选择，请重新输入。[/red]")

if __name__ == "__main__":
    main_menu()






































