import nmap
import json
import os
from datetime import datetime

def scan_host(target, arguments):
    nm = nmap.PortScanner()
    nm.scan(target, arguments=arguments)
    return nm

def convert_scan_to_dict(scan_result):
    result_dict = {}
    for host in scan_result.all_hosts():
        result_dict[host] = {
            "hostnames": scan_result[host].hostnames(),
            "addresses": scan_result[host].get('addresses', {}),
            "vendor": scan_result[host].get('vendor', {}),
            "status": scan_result[host].state(),
            "tcp": scan_result[host].get('tcp', {}),
            "udp": scan_result[host].get('udp', {}),
            "osmatch": scan_result[host].get('osmatch', [])
        }
    return result_dict

def save_results_to_json(scan_result, target, scan_type):
    result_dict = convert_scan_to_dict(scan_result)
    output_dir = './results'
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    output_path = os.path.join(output_dir, f"nmap_scan_results_{target}_{scan_type}_{timestamp}.json")
    with open(output_path, 'w', encoding='utf-8') as file:
        json.dump(result_dict, file, ensure_ascii=False, indent=4)
    print(f"Results saved to {output_path}")

def read_targets(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        targets = [line.strip() for line in file if line.strip()]
    return targets

def main():
    file_path = input("请输入包含目标列表的文件路径（例如：targets.txt）：")
    targets = read_targets(file_path)

    scans = {
        "-name": "-sL",
        "-port": "-sS",
        "-ftp": "-p 21 --script=ftp-anon,ftp-brute,ftp-bounce",
        "-ssh": "-p 22 --script=ssh-hostkey",
        "-telnet": "-p 23 --script=telnet-brute,telnet-ntlm-info",
        "-smtp": "-p 25 --script=smtp-commands,smtp-enum-users,smtp-brute",
        "-finger": "-p 79 --script=finger",
        "-iis": "--script=http-iis-short-name-brute",
        "-cgi": "--script=http-vuln-cve2010-0738,http-vuln-cve2011-3192",
        "-pop": "-p 110 --script=pop3-capabilities,pop3-brute",
        "-rpc": "-p 111 --script=rpcinfo",
        "-ipc": "-p 135 --script=msrpc-enum,nfs-ls",
        "-imap": "-p 143 --script=imap-capabilities,imap-brute",
        "-mssql": "-p 1433 --script=ms-sql-brute",
        "-mysql": "-p 3306 --script=mysql-info,mysql-brute",
        "-cisco": "--script=cisco-enum-users,cisco-brute",
        "-plugin": "--script=all"
    }

    for target in targets:
        for scan_type, args in scans.items():
            print(f"正在对 {target} 进行 {scan_type} 扫描...")
            try:
                scan_result = scan_host(target, args)
                save_results_to_json(scan_result, target, scan_type)
            except Exception as e:
                print(f"扫描 {target} 时出错：{e}")

if __name__ == "__main__":
    main()


 
