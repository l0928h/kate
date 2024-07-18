import argparse
from pymetasploit3.msfrpc import MsfRpcClient
import time

def list_all_modules(client):
    """
    列出所有可用的模块
    """
    module_types = {
        'exploit': client.modules.exploits,
        'auxiliary': client.modules.auxiliary,
        'post': client.modules.post,
        'payload': client.modules.payloads,
        'encoder': client.modules.encoders,
        'nop': client.modules.nops
    }
    
    for module_type, modules in module_types.items():
        try:
            print(f"\nListing {module_type} modules:")
            print("{:<5} {:<70} {:<15} {:<10} {:<6}".format("ID", "Name", "Disclosure Date", "Rank", "Check"))
            print("-" * 110)
            for idx, module in enumerate(modules):
                mod = client.modules.use(module_type, module)
                name = module
                disclosure_date = mod.info.get('disclosure_date', 'N/A')
                rank = mod.info.get('rank', 'N/A')
                check = 'Yes' if mod.info.get('check', False) else 'No'
                print("{:<5} {:<70} {:<15} {:<10} {:<6}".format(idx, name, disclosure_date, rank, check))
        except Exception as e:
            print(f"Failed to list {module_type} modules: {e}")

def scan_targets(client, targets, scanners):
    """
    扫描指定的目标
    """
    for scanner in scanners:
        for target in targets:
            try:
                print(f"\nAttempting to load module {scanner} for target {target}")
                module = client.modules.use('auxiliary', scanner)
                print(f"Successfully loaded module {scanner}")
                print(f"Module options: {module.options}")

                # 设置已知的选项 RHOSTS 和其他相关选项
                if 'RHOSTS' in module.options:
                    module['RHOSTS'] = target
                    print(f"Successfully set RHOSTS to {target}")
                else:
                    print(f"Module {scanner} does not have a RHOSTS option")
                    continue
                
                print(f"Executing module {scanner} on target {target}...")
                job_id = module.execute()
                print(f"Started job {job_id} for scanner {scanner} on target {target}")

                # 等待并检查扫描结果
                time.sleep(5)  # 等待一段时间以获取初步结果

                # 获取并显示扫描结果
                result = client.jobs.info(job_id)
                print(f"Job {job_id} finished with result: {result}")

                # 检查并处理扫描模块的具体结果
                if 'data' in result:
                    print(f"Scan data: {result['data']}")
                else:
                    print(f"No data found for job {job_id}")

                # 打印扫描过程中收集的详细信息
                if 'log' in result:
                    logs = result['log']
                    for log in logs:
                        print(log)
                else:
                    print(f"No log data found for job {job_id}")

            except Exception as e:
                print(f"Failed to start job for scanner {scanner} on target {target}: {e}")

            finally:
                # 停止该任务以便清理环境
                try:
                    client.jobs.stop(job_id)
                except Exception as e:
                    print(f"Failed to stop job {job_id}: {e}")

def load_targets_from_file(file_path):
    """
    从文件中加载目标IP地址
    """
    try:
        with open(file_path, 'r') as file:
            targets = [line.strip() for line in file if line.strip()]
        print(f"Loaded targets from file {file_path}: {targets}")
        return targets
    except Exception as e:
        print(f"Failed to read targets from file {file_path}: {e}")
        return []

def load_modules_from_file(file_path):
    """
    从文件中加载模块名称
    """
    try:
        with open(file_path, 'r') as file:
            modules = [line.strip() for line in file if line.strip()]
        print(f"Loaded modules from file {file_path}: {modules}")
        return modules
    except Exception as e:
        print(f"Failed to read modules from file {file_path}: {e}")
        return []

def main():
    parser = argparse.ArgumentParser(description="Metasploit Automation Script")
    parser.add_argument('--list-modules', action='store_true', help="List all available modules")
    parser.add_argument('--scan', action='store_true', help="Scan specified targets")
    parser.add_argument('--targets', nargs='+', help="List of target IPs")
    parser.add_argument('--modules', nargs='+', help="List of modules to use for scanning")
    parser.add_argument('--target-file', type=str, help="File containing target IPs")
    parser.add_argument('--module-file', type=str, help="File containing module names")

    args = parser.parse_args()

    # 连接到Metasploit RPC服务器
    print("Connecting to Metasploit RPC server...")
    client = MsfRpcClient('password', port=55552)
    print("Connected to Metasploit RPC server.")

    if args.list_modules:
        list_all_modules(client)

    if args.scan:
        targets = args.targets or []
        if args.target_file:
            targets.extend(load_targets_from_file(args.target_file))
        
        modules = args.modules or []
        if args.module_file:
            modules.extend(load_modules_from_file(args.module_file))
        
        if not targets or not modules:
            parser.error("--scan requires --targets or --target-file and --modules or --module-file arguments.")
        
        print(f"Starting scan on targets: {targets} with modules: {modules}")
        scan_targets(client, targets, modules)

if __name__ == '__main__':
    main()
















         









