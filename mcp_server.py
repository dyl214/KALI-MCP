#!/usr/bin/env python3

import sys
import os
import argparse
import logging
from typing import Dict, Any, Optional
from pydantic import Field
import requests

from mcp.server.fastmcp import FastMCP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Default configuration
DEFAULT_KALI_SERVER = "http://192.168.18.128:5000" # change to your linux IP
DEFAULT_REQUEST_TIMEOUT = 300  # 5 minutes default timeout for API requests

class KaliToolsClient:
    """Client for communicating with the Kali Linux Tools API Server"""
    
    def __init__(self, server_url: str, timeout: int = DEFAULT_REQUEST_TIMEOUT):
        """
        Initialize the Kali Tools Client
        
        Args:
            server_url: URL of the Kali Tools API Server
            timeout: Request timeout in seconds
        """
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        logger.info(f"Initialized Kali Tools Client connecting to {server_url}")
        
    def safe_get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Perform a GET request with optional query parameters.
        
        Args:
            endpoint: API endpoint path (without leading slash)
            params: Optional query parameters
            
        Returns:
            Response data as dictionary
        """
        if params is None:
            params = {}

        url = f"{self.server_url}/{endpoint}"

        try:
            logger.debug(f"GET {url} with params: {params}")
            response = requests.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"请求失败: {str(e)}")
            return {"error": f"请求失败: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"意外错误: {str(e)}")
            return {"error": f"意外错误: {str(e)}", "success": False}

    def safe_post(self, endpoint: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform a POST request with JSON data.
        
        Args:
            endpoint: API endpoint path (without leading slash)
            json_data: JSON data to send
            
        Returns:
            Response data as dictionary
        """
        url = f"{self.server_url}/{endpoint}"
        
        try:
            logger.debug(f"POST {url} with data: {json_data}")
            response = requests.post(url, json=json_data, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            return {"error": f"请求失败: {str(e)}", "success": False}
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return {"error": f"Unexpected error: {str(e)}", "success": False}

    def execute_command(self, command: str) -> Dict[str, Any]:
        """
        Execute a generic command on the Kali server
        
        Args:
            command: Command to execute
            
        Returns:
            命令执行结果
        """
        return self.safe_post("api/command", {"command": command})
    
    def check_health(self) -> Dict[str, Any]:
        """
        Check the health of the Kali Tools API Server
        
        Returns:
            Health status information
        """
        return self.safe_get("health")

def setup_mcp_server(kali_client: KaliToolsClient) -> FastMCP:
    """
    Set up the MCP server with all tool functions
    
    Args:
        kali_client: Initialized KaliToolsClient
        
    Returns:
        Configured FastMCP instance
    """
    mcp = FastMCP("kali-mcp")
    
    @mcp.tool()
    def nmap_scan(
    target: str = Field(..., description="目标IP地址或主机名"),
    scan_type: str = Field("-sV", description="扫描类型（例如，-sV用于版本检测）"),
    ports: str = Field("", description="逗号分隔的端口列表或端口范围"),
    additional_args: str = Field("", description="Nmap的额外参数")
) -> Dict[str, Any]:
        """
        对目标执行Nmap扫描。
        
        Args:
            target: 目标IP地址或主机名
            scan_type: 扫描类型（例如，-sV用于版本检测）
            ports: 逗号分隔的端口列表或端口范围
            additional_args: Nmap的额外参数
            
        Returns:
            Scan results
        """
        if not target:
            raise ValueError("目标参数是必需的")
        data = {
            "target": target,
            "scan_type": scan_type,
            "ports": ports,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/nmap", data)

    @mcp.tool()
    def gobuster_scan(url: str = "", mode: str = "dir", wordlist: str = None, domain: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        执行Gobuster以查找目录、DNS子域名或虚拟主机。
        
        Args:
            url: The target URL (for dir mode)
            mode: Scan mode (dir or dns)
            wordlist: Path to wordlist file
            domain: The target domain (for dns mode)
            additional_args: Additional Gobuster arguments
            
        Returns:
            Scan results
        """
        # Validate inputs
        if mode == "dns" and not domain:
            raise ValueError("DNS模式需要domain参数")
        if mode == "dir" and not url:
            raise ValueError("目录模式需要url参数")
        
        # Prepare parameters
        data = {
            "mode": mode,
            "additional_args": additional_args
        }
        
        if wordlist:
            data["wordlist"] = wordlist
        
        if mode == "dir" and url:
            data["url"] = url
        if mode == "dns" and domain:
            data["domain"] = domain
        
        # Execute the scan
        return kali_client.safe_post("api/tools/gobuster", data)

    @mcp.tool()
    def nikto_scan(target: str, additional_args: str = "") -> Dict[str, Any]:
        """
        执行Nikto web服务器扫描器。
        
        Args:
            target: The target URL or IP
            additional_args: Additional Nikto arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/nikto", data)

    @mcp.tool()
    def sqlmap_scan(url: str, data: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        执行SQLmap SQL注入扫描器。
        
        Args:
            url: The target URL
            data: POST data string
            additional_args: Additional SQLmap arguments
            
        Returns:
            Scan results
        """
        post_data = {
            "url": url,
            "data": data,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/sqlmap", post_data)

    @mcp.tool()
    def metasploit_run(module: str, options: Dict[str, Any] = {}) -> Dict[str, Any]:
        """
        执行Metasploit模块。
        
        Args:
            module: The Metasploit module path
            options: Dictionary of module options
            
        Returns:
            Module execution results
        """
        data = {
            "module": module,
            "options": options
        }
        return kali_client.safe_post("api/tools/metasploit", data)

    @mcp.tool()
    def hydra_attack(
        target: str, 
        service: str, 
        username: str = "", 
        username_file: str = "", 
        password: str = "", 
        password_file: str = "", 
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        执行Hydra密码破解工具。
        
        Args:
            target: Target IP or hostname
            service: Service to attack (ssh, ftp, http-post-form, etc.)
            username: Single username to try
            username_file: Path to username file
            password: Single password to try
            password_file: Path to password file
            additional_args: Additional Hydra arguments
            
        Returns:
            Attack results
        """
        data = {
            "target": target,
            "service": service,
            "username": username,
            "username_file": username_file,
            "password": password,
            "password_file": password_file,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/hydra", data)

    @mcp.tool()
    def john_crack(
        hash_file: str, 
        wordlist: str = "/usr/share/wordlists/rockyou.txt", 
        format_type: str = "", 
        additional_args: str = ""
    ) -> Dict[str, Any]:
        """
        执行John the Ripper密码破解器。
        
        Args:
            hash_file: Path to file containing hashes
            wordlist: Path to wordlist file
            format_type: Hash format type
            additional_args: Additional John arguments
            
        Returns:
            Cracking results
        """
        data = {
            "hash_file": hash_file,
            "wordlist": wordlist,
            "format": format_type,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/john", data)

    @mcp.tool()
    def wpscan_analyze(url: str, additional_args: str = "") -> Dict[str, Any]:
        """
        执行WPScan WordPress漏洞扫描器。
        
        Args:
            url: The target WordPress URL
            additional_args: Additional WPScan arguments
            
        Returns:
            Scan results
        """
        data = {
            "url": url,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/wpscan", data)

    @mcp.tool(name="subfinder_scan")
    def subfinder_scan(target: str, timeout: int = 300, additional_args: str = "") -> Dict[str, Any]:
        # 修复工具注册问题
        """
        执行subfinder进行子域名枚举。
        
        Args:
            target: The domain to enumerate subdomains for
            timeout: Timeout in seconds
            additional_args: Additional subfinder arguments
            
        Returns:
            Enumeration results
        """
        data = {
            "target": target,
            "timeout": timeout,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/subfinder", data)

    @mcp.tool()
    def dirsearch_scan(url: str, wordlist: str = "/usr/share/wordlists/dirsearch/common.txt", threads: int = 10, additional_args: str = "") -> Dict[str, Any]:
        """
        执行dirsearch进行目录扫描。
        
        Args:
            url: The target URL
            wordlist: Path to wordlist file
            threads: Number of threads to use
            additional_args: Additional dirsearch arguments
            
        Returns:
            Scan results
        """
        data = {
            "url": url,
            "wordlist": wordlist,
            "threads": threads,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/dirsearch", data)

    @mcp.tool(name="amass_scan")
    def amass_scan(domain: str, enum: str = "sub", additional_args: str = "") -> Dict[str, Any]:
        """
        执行Amass进行子域名枚举。
        
        Args:
            domain: The domain to enumerate
            enum: Enumeration type (sub, asn, etc.)
            additional_args: Additional Amass arguments
            
        Returns:
            Enumeration results
        """
        data = {
            "domain": domain,
            "enum": enum,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/amass", data)

    @mcp.tool()
    def nuclei_scan(target: str, templates: str = "", severity: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        执行Nuclei基于模板的漏洞扫描。
        
        Args:
            target: The target URL or domain
            templates: Comma-separated list of templates to use
            severity: Filter vulnerabilities by severity (low, medium, high, critical)
            additional_args: Additional Nuclei arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "templates": templates,
            "severity": severity,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/nuclei", data)

    @mcp.tool()
    def whatweb_scan(target: str, additional_args: str = "") -> Dict[str, Any]:
        """
        执行WhatWeb进行网站技术检测。
        
        Args:
            target: The target URL
            additional_args: Additional WhatWeb arguments
            
        Returns:
            Technology detection results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/whatweb", data)

    @mcp.tool()
    def ffuf_scan(url: str, wordlist: str = "/usr/share/wordlists/ffuf/common.txt", threads: int = 10, additional_args: str = "") -> Dict[str, Any]:
        """
        执行ffuf进行Web模糊测试。
        
        Args:
            url: The target URL with FUZZ keyword
            wordlist: Path to wordlist file
            threads: Number of threads
            additional_args: Additional ffuf arguments
            
        Returns:
            Fuzzing results
        """
        data = {
            "url": url,
            "wordlist": wordlist,
            "threads": threads,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/ffuf", data)

    @mcp.tool()
    def masscan_scan(target: str, ports: str = "1-65535", rate: int = 1000, additional_args: str = "") -> Dict[str, Any]:
        """
        执行masscan进行快速端口扫描。
        
        Args:
            target: The target IP or CIDR
            ports: Port range to scan
            rate: Packets per second rate
            additional_args: Additional masscan arguments
            
        Returns:
            Scan results
        """
        data = {
            "target": target,
            "ports": ports,
            "rate": rate,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/masscan", data)

    @mcp.tool()
    def gau_scan(domain: str, additional_args: str = "") -> Dict[str, Any]:
        """
        执行gau从Wayback Machine、Common Crawl和VirusTotal获取URL。
        
        Args:
            domain: The target domain
            additional_args: Additional gau arguments
            
        Returns:
            URL results
        """
        data = {
            "domain": domain,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/gau", data)

    @mcp.tool()
    def dnsx_scan(domain: str, resolve: bool = True, additional_args: str = "") -> Dict[str, Any]:
        """
        执行dnsx进行DNS解析和枚举。
        
        Args:
            domain: The target domain
            resolve: Whether to resolve DNS records
            additional_args: Additional dnsx arguments
            
        Returns:
            DNS resolution results
        """
        data = {
            "domain": domain,
            "resolve": resolve,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/dnsx", data)

    @mcp.tool()
    def wafw00f_scan(target: str, additional_args: str = "") -> Dict[str, Any]:
        """
        执行wafw00f检测Web应用防火墙。
        
        Args:
            target: The target URL
            additional_args: Additional wafw00f arguments
            
        Returns:
            WAF detection results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/wafw00f", data)

    @mcp.tool()
    def xsstrike_scan(url: str, additional_args: str = "") -> Dict[str, Any]:
        """
        执行XSStrike进行XSS漏洞扫描。
        
        Args:
            url: The target URL with parameters
            additional_args: Additional XSStrike arguments
            
        Returns:
            XSS scan results
        """
        data = {
            "url": url,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/xsstrike", data)

    @mcp.tool()
    def gospider_scan(url: str, threads: int = 5, additional_args: str = "") -> Dict[str, Any]:
        """
        执行gospider进行Web爬虫和URL发现。
        
        Args:
            url: The target URL
            threads: Number of threads
            additional_args: Additional gospider arguments
            
        Returns:
            Spider results with discovered URLs
        """
        data = {
            "url": url,
            "threads": threads,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/gospider", data)

    @mcp.tool()
    def httpx_scan(target: str, probes: str = "title,status-code", additional_args: str = "") -> Dict[str, Any]:
        """
        执行httpx进行HTTP探测和信息收集。
        
        Args:
            target: The target URL or domain
            probes: Comma-separated list of probes to use
            additional_args: Additional httpx arguments
            
        Returns:
            HTTP probe results
        """
        data = {
            "target": target,
            "probes": probes,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/httpx", data)

    @mcp.tool()
    def arjun_scan(url: str, method: str = "GET", threads: int = 5, additional_args: str = "") -> Dict[str, Any]:
        """
        执行arjun进行URL参数发现。
        
        Args:
            url: The target URL
            method: HTTP method (GET/POST)
            threads: Number of threads
            additional_args: Additional arjun arguments
            
        Returns:
            Discovered parameters results
        """
        data = {
            "url": url,
            "method": method,
            "threads": threads,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/arjun", data)

    @mcp.tool()
    def dirb_scan(url: str, wordlist: str = "/usr/share/wordlists/dirb/common.txt", additional_args: str = "") -> Dict[str, Any]:
        """
        执行Dirb进行目录暴力破解。
        
        Args:
            url: The target URL
            wordlist: Path to wordlist file
            additional_args: Additional Dirb arguments
            
        Returns:
            Scan results
        """
        data = {
            "url": url,
            "wordlist": wordlist,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/dirb", data)

    @mcp.tool()
    def theHarvester_scan(domain: str, sources: str = "google,bing,linkedin", limit: int = 500, additional_args: str = "") -> Dict[str, Any]:
        """
        执行theHarvester进行信息收集。
        
        Args:
            domain: Target domain
            sources: Comma-separated list of sources (google, bing, etc.)
            limit: Maximum results to fetch
            additional_args: Additional theHarvester arguments
            
        Returns:
            Information gathering results
        """
        data = {
            "domain": domain,
            "sources": sources,
            "limit": limit,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/theHarvester", data)

    @mcp.tool()
    def cewl_scan(url: str, min_length: int = 5, wordlist: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        执行Cewl从网页内容生成字典。
        
        Args:
            url: Target URL to crawl
            min_length: Minimum word length
            wordlist: Output wordlist file path (optional)
            additional_args: Additional Cewl arguments
            
        Returns:
            Wordlist generation results
        """
        data = {
            "url": url,
            "min_length": min_length,
            "wordlist": wordlist,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/cewl", data)

    @mcp.tool()
    def whois_scan(domain: str, additional_args: str = "") -> Dict[str, Any]:
        """
        执行whois域名查询工具。
        
        Args:
            domain: Target domain name
            additional_args: Additional whois arguments
            
        Returns:
            Domain registration information
        """
        data = {
            "domain": domain,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/whois", data)

    @mcp.tool()
    def dig_scan(domain: str, record_type: str = "A", additional_args: str = "") -> Dict[str, Any]:
        """
        执行dig DNS查询工具。
        
        Args:
            domain: Target domain name
            record_type: DNS record type (A, AAAA, NS, etc.)
            additional_args: Additional dig arguments
            
        Returns:
            DNS query results
        """
        data = {
            "domain": domain,
            "record_type": record_type,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/dig", data)

    @mcp.tool()
    def enum4linux_scan(target: str, additional_args: str = "-a") -> Dict[str, Any]:
        """
        执行Enum4linux Windows/Samba枚举工具。
        
        Args:
            target: 目标IP或主机名
            additional_args: enum4linux的额外参数
            
        Returns:
            Enumeration results
        """
        data = {
            "target": target,
            "additional_args": additional_args
        }
        return kali_client.safe_post("api/tools/enum4linux", data)

    @mcp.tool()
    def server_health() -> Dict[str, Any]:
        """
        检查Kali API服务器的健康状态。
        
        Returns:
            Server health information
        """
        return kali_client.check_health()
    
    @mcp.tool()
    def execute_command(command: str) -> Dict[str, Any]:
        """
        在Kali服务器上执行任意命令。
        
        Args:
            command: 要执行的命令
            
        Returns:
            Command execution results
        """
        return kali_client.execute_command(command)

    return mcp

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="运行Kali MCP客户端")
    parser.add_argument("--server", type=str, default=DEFAULT_KALI_SERVER, 
                      help=f"Kali API服务器URL（默认： {DEFAULT_KALI_SERVER})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT,
                      help=f"请求超时时间（秒）（默认： {DEFAULT_REQUEST_TIMEOUT})")
    parser.add_argument("--debug", action="store_true", help="启用调试日志")
    return parser.parse_args()

def main():
    """Main entry point for the MCP server."""
    args = parse_args()
    
    # Configure logging based on debug flag
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.debug("已启用调试日志")
    
    # Initialize the Kali Tools client
    kali_client = KaliToolsClient(args.server, args.timeout)
    
    # Check server health and log the result
    health = kali_client.check_health()
    if "error" in health:
        logger.warning(f"无法连接到Kali API服务器： {args.server}: {health['error']}")
        logger.warning("MCP服务器将启动，但工具执行可能失败")
    else:
        logger.info(f"成功连接到Kali API服务器： {args.server}")
        logger.info(f"服务器健康状态： {health['status']}")
        if not health.get("all_essential_tools_available", False):
            logger.warning("Kali服务器上并非所有必要工具都可用")
            missing_tools = [tool for tool, available in health.get("tools_status", {}).items() if not available]
            if missing_tools:
                logger.warning(f"缺少的工具： {', '.join(missing_tools)}")
    
    # Set up and run the MCP server
    mcp = setup_mcp_server(kali_client)
    logger.info("启动Kali MCP服务器")
    mcp.run()

if __name__ == "__main__":
    main()
