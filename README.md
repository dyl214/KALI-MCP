# MCP Kali Server (二次修改版)

**Kali MCP Server (二次修改版)** 是一个轻量级API桥接工具，用于连接MCP客户端与Kali Linux终端，允许执行命令和安全测试工具。本项目基于原始版本进行了二次开发，增强了工具调用能力并优化了中文支持。

本项目是基于原项目的二次修改版本，主要增强了MCP调用Kali工具的种类和数量，提供更全面的安全测试能力。通过AI辅助，可以实时执行渗透测试、解决CTF挑战，或完成HTB/THM等平台的机器测试任务。

## 二次修改主要增强
- 扩展支持的Kali工具种类，从基础命令扩展到30+专业安全测试工具
- 优化中文错误提示和用户界面
- 改进工具调用参数验证和错误处理
- 增加更多工具的API端点支持

## 支持的Kali工具列表
本项目支持调用以下Kali Linux安全测试工具：

### 网络扫描与枚举
- **nmap** - 网络发现和安全扫描
- **masscan** - 高速端口扫描器
- **amass** - 子域名枚举工具
- **subfinder** - 子域名发现工具
- **dnsx** - DNS解析和枚举工具
- **whatweb** - 网站技术检测
- **httpx** - HTTP探测工具

### 漏洞扫描与利用
- **nikto** - Web服务器漏洞扫描器
- **nuclei** - 基于模板的漏洞扫描器
- **wpscan** - WordPress漏洞扫描器
- **sqlmap** - SQL注入检测与利用工具
- **xsstrike** - XSS漏洞扫描器
- **metasploit** - 漏洞利用框架

### 目录与文件爆破
- **gobuster** - 目录和子域名爆破工具
- **dirsearch** - 目录扫描工具
- **dirb** - 目录暴力破解工具
- **ffuf** - Web模糊测试工具
- **arjun** - URL参数发现工具

### 密码攻击
- **hydra** - 密码破解工具
- **john** - 密码哈希破解工具

### 信息收集
- **theHarvester** - 电子邮件和子域名收集
- **cewl** - 从网页内容生成密码字典
- **whois** - 域名注册信息查询
- **dig** - DNS查询工具
- **enum4linux** - Windows/Samba枚举工具
- **gospider** - Web爬虫和URL发现
- **gau** - 从Wayback Machine等来源获取URL
- **wafw00f** - Web应用防火墙检测

## 使用方法

### 在Kali Linux机器上（作为MCP服务器）
```bash
# 克隆仓库
 git clone https://github.com/dyl214/KALI-MCP.git

# 启动服务器
 python3 kali_server.py
```

### 在MCP客户端上（Windows或Linux）
运行客户端连接到Kali服务器：
```bash
python3 /绝对路径/mcp_server.py http://KALI_IP:5000
```

#### Claude Desktop配置

```json
{
    "mcpServers": {
        "kali_mcp": {
            "command": "python3",
            "args": [
                "/绝对路径/mcp_server.py",
                "--server",
                "http://KALI_IP:5000/"
            ]
        }
    }
}
```

#### [5ire](https://github.com/nanbingxyz/5ire) 桌面应用配置
添加新的MCP，命令为：
```bash
python3 /绝对路径/mcp_server.py http://KALI_IP:5000
```

## 项目总结

Kali MCP Server是一个轻量级API桥接工具，用于连接MCP客户端与Kali Linux终端，实现安全测试工具的远程调用与管理。本项目是在原始版本基础上进行的二次开发，主要增强了MCP调用Kali工具的种类和数量，并优化了中文用户界面和提示信息。

## 功能特点
- **AI端点集成**：连接Kali与任意MCP客户端
- **命令执行API**：安全可控的终端命令执行接口
- **Web挑战支持**：通过curl等工具与网站交互
- **全面的工具集**：支持30+专业安全测试工具

## 使用方法

### 1. 环境准备
- 部署Kali Linux服务器
- 安装必要依赖包
- 配置网络连接

### 2. 服务器配置
```bash
# 克隆项目仓库
git clone https://github.com/yourusername/MCP-Kali.git
cd MCP-Kali

# 安装依赖
pip install -r requirements.txt

# 启动服务
python kali_server.py
```

### 3. 客户端连接
配置MCP客户端连接到Kali服务器，根据客户端类型设置相应参数。

## 免责声明
本项目仅用于教育和合法的安全测试目的。严禁将本工具用于未经授权的访问、利用或恶意活动。作者对任何不当使用不承担责任。
