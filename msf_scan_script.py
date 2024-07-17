from metasploit.msfrpc import MsfRpcClient
import time

# 连接到Metasploit RPC服务器
client = MsfRpcClient('password', port=55552)

# 定义要扫描的主机
targets = ['192.168.1.1', '192.168.1.2', '192.168.1.3']

# 定义要使用的扫描模块
scanners = [
    'auxiliary/scanner/vuln/ms17_010_eternalblue',
    'auxiliary/scanner/http/apache_struts2_rce'
]

# 遍历每个扫描模块和目标
for scanner in scanners:
    for target in targets:
        module = client.modules.use('auxiliary', scanner)
        module['RHOSTS'] = target
        job_id = module.execute()
        print(f"Started job {job_id} for scanner {scanner} on target {target}")

# 检查扫描结果
time.sleep(10) # 等待扫描完成
for job_id in client.jobs.list.keys():
    result = client.jobs.info(job_id)
    print(f"Job {job_id} finished with result: {result}")
