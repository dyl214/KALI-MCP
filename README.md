# MCP Kali Server (二次修改版)

原项目地址https://github.com/Wh0am123/MCP-Kali-Server

**Kali MCP Server (二次修改版)** 用于连接MCP客户端与Kali Linux终端，允许执行命令和安全测试工具。本项目基于原始版本进行了二次开发，增强了工具调用能力并优化了中文支持。

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
运行客户端连接到Kali服务器：（这里使用Trae）
点击箭头所指

<img width="456" height="184" alt="QQ_1757505425930" src="https://github.com/user-attachments/assets/689b6abe-ecd2-4164-9d4e-6b83779b0f8f" />

使用内置mcp智能体

<img width="493" height="235" alt="QQ_1757505565713" src="https://github.com/user-attachments/assets/d4e24d68-7ac5-43bf-b1e0-ed98e7a12ee5" />

然后需要进行配置，点击创建智能体->MCP->添加->手动添加

<img width="483" height="192" alt="QQ_1757505620373" src="https://github.com/user-attachments/assets/5987b65c-f5d2-4040-9bfd-a556218c8478" />

将下方的json配置放上去即可

<img width="472" height="697" alt="QQ_1757505740329" src="https://github.com/user-attachments/assets/28bc4610-c6ef-4911-ae13-c3bbdc9fbac3" />

然后运行mcp_sever.py，连接kali，向模型说明要求即可


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


## 免责声明
本项目仅用于教育和合法的安全测试目的。严禁将本工具用于未经授权的访问、利用或恶意活动。作者对任何不当使用不承担责任。
