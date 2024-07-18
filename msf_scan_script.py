from pymetasploit3.msfrpc import MsfRpcClient
import time

# 连接到Metasploit RPC服务器
client = MsfRpcClient('password', port=55552)

# 定义要扫描的主机
targets = ['122.10.110.174', '154.93.166.93', '154.218.67.139']  # 添加多个目标以测试

# 定义要使用的扫描模块（此处使用不同的模块示例）
scanners = [
    'auxiliary/scanner/smb/smb_ms17_010'
]

# 遍历每个扫描模块和目标
for scanner in scanners:
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
            client.jobs.stop(job_id)

print("Scanning completed.")







