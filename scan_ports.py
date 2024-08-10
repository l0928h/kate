import nmap
import os
import argparse

# 设置命令行参数解析
parser = argparse.ArgumentParser(description='Perform nmap scan and categorize results by open ports.')
parser.add_argument('-t', '--target_file', type=str, required=True, help='Path to the target file containing IPs or domain names.')
parser.add_argument('-o', '--output_dir', type=str, default='port_results/', help='Directory to save port results.')

args = parser.parse_args()

# 目标列表文件路径和结果目录路径
target_file = args.target_file
output_dir = args.output_dir

# 创建结果目录
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

# 初始化nmap扫描器
nm = nmap.PortScanner()

# 打开目标文件并逐行读取目标IP或域名
with open(target_file, 'r') as tf:
    targets = tf.readlines()

# 字典用于存储每个端口对应的主机列表
port_dict = {}

# 遍历每个目标并执行扫描
for target in targets:
    target = target.strip()
    print(f"Scanning {target}...")
    
    # 执行端口扫描
    nm.scan(target, '1-65535', '-T4 -n --min-rate=1000 --max-retries=1')
    
    # 遍历扫描结果
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                if nm[host][proto][port]['state'] == 'open':
                    # 将每个开放端口记录到对应的列表中
                    if port not in port_dict:
                        port_dict[port] = []
                    port_dict[port].append(host)

# 将结果写入不同的文件中
for port, hosts in port_dict.items():
    with open(f"{output_dir}/port_{port}.txt", 'w') as pf:
        for host in hosts:
            pf.write(f"{host}\n")

print("Scanning complete. Results saved in separate files for each port.")
