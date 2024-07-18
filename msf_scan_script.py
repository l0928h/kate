import argparse
from pymetasploit3.msfrpc import MsfRpcClient
import time

def list_all_modules(client):
    """
    列出所有可用的模块
    """
    try:
        exploits = client.modules.exploits
        auxiliaries = client.modules.auxiliary
        posts = client.modules.post
        payloads = client.modules.payloads
        encoders = client.modules.encoders
        nops = client.modules.nops

        print("\nListing exploit modules:")
        for module in exploits:
            print(module)

        print("\nListing auxiliary modules:")
        for module in auxiliaries:
            print(module)

        print("\nListing post modules:")
        for module in posts:
            print(module)

        print("\nListing payload modules:")
        for module in payloads:
            print(module)

        print("\nListing encoder modules:")
        for module in encoders:
            print(module)

        print("\nListing nop modules:")
        for module in nops:
            print(module)

    except Exception as e:
        print(f"Failed to list modules: {e}")

def scan_targets(client, targets, scanner):
    """
    扫描指定的目标
    """
    for target in targets:
        try:
            print(f"\nAttempting to load module {scanner}")
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

def main():
    parser = argparse.ArgumentParser(description="Metasploit Automation Script")
    parser.add_argument('--list-modules', action='store_true', help="List all available modules")
    parser.add_argument('--scan', action='store_true', help="Scan specified targets")
    parser.add_argument('--targets', nargs='+', help="List of target IPs")
    parser.add_argument('--module', type=str, help="Module to use for scanning")

    args = parser.parse_args()

    # 连接到Metasploit RPC服务器
    client = MsfRpcClient('password', port=55552)

    if args.list_modules:
        list_all_modules(client)

    if args.scan:
        if not args.targets or not args.module:
            parser.error("--scan requires --targets and --module arguments.")
        scan_targets(client, args.targets, args.module)

if __name__ == '__main__':
    main()








         









