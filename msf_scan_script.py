from pymetasploit3.msfrpc import MsfRpcClient
import time

# 连接到Metasploit RPC服务器
client = MsfRpcClient('password', port=55552)

# 定义要扫描的主机
targets = ['122.10.110.174']

# 定义要使用的扫描模块
scanners = [
    'auxiliary/scanner/smb/smb_ms17_010'
]

# 遍历每个扫描模块和目标
for scanner in scanners:
    for target in targets:
        try:
            print(f"Attempting to load module {scanner}")
            module = client.modules.use('auxiliary', scanner)
            print(f"Successfully loaded module {scanner}")
            print(f"Module options: {module.options}")

            # 设置已知的选项 RHOSTS
            if 'RHOSTS' in module.options:
                module['RHOSTS'] = target
                print(f"Successfully set RHOSTS to {target}")
            else:
                print(f"Module {scanner} does not have a RHOSTS option")
                continue
            
            job_id = module.execute()
            print(f"Started job {job_id} for scanner {scanner} on target {target}")
        except Exception as e:
            print(f"Failed to start job for scanner {scanner} on target {target}: {e}")

# 检查扫描结果
time.sleep(10) # 等待扫描完成
for job_id in client.jobs.list.keys():
    result = client.jobs.info(job_id)
    print(f"Job {job_id} finished with result: {result}")



