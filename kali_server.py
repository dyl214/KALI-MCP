#!/usr/bin/env python3

# 此脚本将MCP AI代理连接到Kali Linux终端和API服务器。

# 此代码的部分灵感来自 https://github.com/whit3rabbit0/project_astro ，请务必查看该项目

import argparse
import json
import logging
import os
import subprocess
import sys
import traceback
import threading
from typing import Dict, Any
from flask import Flask, request, jsonify

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Configuration
API_PORT = int(os.environ.get("API_PORT", 5000))
DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")
COMMAND_TIMEOUT = 180  # 5 minutes default timeout

app = Flask(__name__)

class CommandExecutor:
    """用于处理命令执行并提供更好的超时管理的类"""
    
    def __init__(self, command: str, timeout: int = COMMAND_TIMEOUT):
        self.command = command
        self.timeout = timeout
        self.process = None
        self.stdout_data = ""
        self.stderr_data = ""
        self.stdout_thread = None
        self.stderr_thread = None
        self.return_code = None
        self.timed_out = False
    
    def _read_stdout(self):
        """持续读取标准输出的线程函数"""
        for line in iter(self.process.stdout.readline, ''):
            self.stdout_data += line
    
    def _read_stderr(self):
        """持续读取标准错误的线程函数"""
        for line in iter(self.process.stderr.readline, ''):
            self.stderr_data += line
    
    def execute(self) -> Dict[str, Any]:
        """执行命令并处理超时"""
        logger.info(f"执行命令: {self.command}")
        
        try:
            self.process = subprocess.Popen(
                self.command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1  # Line buffered
            )
            
            # Start threads to read output continuously
            self.stdout_thread = threading.Thread(target=self._read_stdout)
            self.stderr_thread = threading.Thread(target=self._read_stderr)
            self.stdout_thread.daemon = True
            self.stderr_thread.daemon = True
            self.stdout_thread.start()
            self.stderr_thread.start()
            
            # Wait for the process to complete or timeout
            try:
                self.return_code = self.process.wait(timeout=self.timeout)
                # Process completed, join the threads
                self.stdout_thread.join()
                self.stderr_thread.join()
            except subprocess.TimeoutExpired:
                # Process timed out but we might have partial results
                self.timed_out = True
                logger.warning(f"命令在{self.timeout}秒后超时。终止进程。")
                
                # Try to terminate gracefully first
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)  # Give it 5 seconds to terminate
                except subprocess.TimeoutExpired:
                    # Force kill if it doesn't terminate
                    logger.warning("进程未响应终止信号。强制终止。")
                    self.process.kill()
                
                # Update final output
                self.return_code = -1
            
            # Always consider it a success if we have output, even with timeout
            success = True if self.timed_out and (self.stdout_data or self.stderr_data) else (self.return_code == 0)
            
            return {
                "stdout": self.stdout_data,
                "stderr": self.stderr_data,
                "return_code": self.return_code,
                "success": success,
                "timed_out": self.timed_out,
                "partial_results": self.timed_out and (self.stdout_data or self.stderr_data)
            }
        
        except Exception as e:
            logger.error(f"Error executing command: {str(e)}")
            logger.error(traceback.format_exc())
            return {
                "stdout": self.stdout_data,
                "stderr": f"Error executing command: {str(e)}\n{self.stderr_data}",
                "return_code": -1,
                "success": False,
                "timed_out": False,
                "partial_results": bool(self.stdout_data or self.stderr_data)
            }


def execute_command(command: str) -> Dict[str, Any]:
    """执行shell命令并返回结果
    
    Args:
        command: 要执行的命令
        
    Returns:
        包含标准输出、标准错误和返回码的字典
    """
    executor = CommandExecutor(command)
    return executor.execute()


@app.route("/api/command", methods=["POST"])
def generic_command():
    """执行请求中提供的任意命令。"""
    try:
        params = request.json
        command = params.get("command", "")
        
        if not command:
            logger.warning("Command endpoint called without command parameter")
            return jsonify({
                "error": "命令参数是必需的"
            }), 400
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in command endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": "服务器错误: {str(e)}"
        }), 500


@app.route("/api/tools/nmap", methods=["POST"])
def nmap():
    """使用提供的参数执行nmap扫描。"""
    try:
        params = request.json
        target = params.get("target", "")
        scan_type = params.get("scan_type", "-sCV")
        ports = params.get("ports", "")
        additional_args = params.get("additional_args", "-T4 -Pn")
        
        if not target:
            logger.warning("Nmap called without target parameter")
            return jsonify({
                "error": "目标参数是必需的"
            }), 400        
        
        command = f"nmap {scan_type}"
        
        if ports:
            command += f" -p {ports}"
        
        if additional_args:
            # Basic validation for additional args - more sophisticated validation would be better
            command += f" {additional_args}"
        
        command += f" {target}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in nmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"服务器错误: {str(e)}"
        }), 500
        


@app.route("/api/tools/subfinder", methods=["POST"])
def subfinder():
    try:
        params = request.json
        target = params.get("target", "")
        timeout = params.get("timeout", 300)
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("Subfinder called without target parameter")
            return jsonify({
                "error": "目标参数是必需的"
            }), 400        
        
        command = f"subfinder -d {target} -timeout {timeout}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in subfinder endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/dirsearch", methods=["POST"])
def dirsearch():
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirsearch/common.txt")
        threads = params.get("threads", 10)
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("Dirsearch called without url parameter")
            return jsonify({
                "error": "URL参数是必需的"
            }), 400        
        
        command = f"dirsearch -u {url} -w {wordlist} -t {threads}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in dirsearch endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/theHarvester", methods=["POST"])
def the_harvester():
    try:
        params = request.json
        domain = params.get("domain", "")
        sources = params.get("sources", "google,bing,linkedin")
        limit = params.get("limit", 500)
        additional_args = params.get("additional_args", "")
        
        if not domain:
            logger.warning("theHarvester called without domain parameter")
            return jsonify({
                "error": "域名参数是必需的"
            }), 400        
        
        command = f"theHarvester -d {domain} -s {sources} -l {limit}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in theHarvester endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/cewl", methods=["POST"])
def cewl():
    try:
        params = request.json
        url = params.get("url", "")
        min_length = params.get("min_length", 5)
        wordlist = params.get("wordlist", "")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("Cewl called without url parameter")
            return jsonify({
                "error": "URL参数是必需的"
            }), 400        
        
        command = f"cewl {url} -m {min_length}"
        
        if wordlist:
            command += f" -w {wordlist}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in cewl endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/whois", methods=["POST"])
def whois():
    try:
        params = request.json
        domain = params.get("domain", "")
        additional_args = params.get("additional_args", "")
        
        if not domain:
            logger.warning("Whois called without domain parameter")
            return jsonify({
                "error": "域名参数是必需的"
            }), 400        
        
        command = f"whois {domain}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in whois endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/dig", methods=["POST"])
def dig():
    try:
        params = request.json
        domain = params.get("domain", "")
        record_type = params.get("record_type", "A")
        additional_args = params.get("additional_args", "")
        
        if not domain:
            logger.warning("Dig called without domain parameter")
            return jsonify({
                "error": "域名参数是必需的"
            }), 400        
        
        command = f"dig {domain} {record_type}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in dig endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in nmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/gobuster", methods=["POST"])
def gobuster():
    """使用提供的参数执行gobuster。"""
    try:
        params = request.json
        mode = params.get("mode", "dir")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")
        
        if mode == "dir":
            url = params.get("url", "")
            if not url:
                logger.warning("Gobuster dir mode called without url parameter")
                return jsonify({"error": "目录模式需要URL参数"}), 400
            command = f"gobuster {mode} -u {url} -w {wordlist}"
        elif mode == "dns":
            domain = params.get("domain", "")
            if not domain:
                logger.warning("Gobuster dns mode called without domain parameter")
                return jsonify({"error": "DNS模式需要域名参数"}), 400
            command = f"gobuster {mode} --domain {domain} -w {wordlist}"
        else:
            return jsonify({"error": "不支持的模式: {mode}"}), 400
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in gobuster endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/dirb", methods=["POST"])
def dirb():
    """Execute dirb with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("Dirb called without URL parameter")
            return jsonify({
                "error": "URL参数是必需的"
            }), 400
        
        command = f"dirb {url} {wordlist}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in dirb endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/nikto", methods=["POST"])
def nikto():
    """Execute nikto with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("Nikto called without target parameter")
            return jsonify({
                "error": "目标参数是必需的"
            }), 400
        
        command = f"nikto -h {target}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in nikto endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/sqlmap", methods=["POST"])
def sqlmap():
    """使用提供的参数执行sqlmap。"""
    try:
        params = request.json
        url = params.get("url", "")
        data = params.get("data", "")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("SQLMap called without URL parameter")
            return jsonify({
                "error": "URL参数是必需的"
            }), 400
        
        command = f"sqlmap -u {url} --batch"
        
        if data:
            command += f" --data=\"{data}\""
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in sqlmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/metasploit", methods=["POST"])
def metasploit():
    """使用提供的参数执行metasploit模块。"""
    try:
        params = request.json
        module = params.get("module", "")
        options = params.get("options", {})
        
        if not module:
            logger.warning("Metasploit called without module parameter")
            return jsonify({
                "error": "模块参数是必需的"
            }), 400
        
        # Format options for Metasploit
        options_str = ""
        for key, value in options.items():
            options_str += f" {key}={value}"
        
        # Create an MSF resource script
        resource_content = f"use {module}\n"
        for key, value in options.items():
            resource_content += f"set {key} {value}\n"
        resource_content += "exploit\n"
        
        # Save resource script to a temporary file
        resource_file = "/tmp/mcp_msf_resource.rc"
        with open(resource_file, "w") as f:
            f.write(resource_content)
        
        command = f"msfconsole -q -r {resource_file}"
        result = execute_command(command)
        
        # Clean up the temporary file
        try:
            os.remove(resource_file)
        except Exception as e:
            logger.warning(f"Error removing temporary resource file: {str(e)}")
        
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in metasploit endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/hydra", methods=["POST"])
def hydra():
    """Execute hydra with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        service = params.get("service", "")
        username = params.get("username", "")
        username_file = params.get("username_file", "")
        password = params.get("password", "")
        password_file = params.get("password_file", "")
        additional_args = params.get("additional_args", "")
        
        if not target or not service:
            logger.warning("Hydra called without target or service parameter")
            return jsonify({
                "error": "目标和服务参数是必需的"
            }), 400
        
        if not (username or username_file) or not (password or password_file):
            logger.warning("Hydra called without username/password parameters")
            return jsonify({
                "error": "用户名/用户名字典和密码/密码字典是必需的"
            }), 400
        
        command = f"hydra -t 4"
        
        if username:
            command += f" -l {username}"
        elif username_file:
            command += f" -L {username_file}"
        
        if password:
            command += f" -p {password}"
        elif password_file:
            command += f" -P {password_file}"
        
        if additional_args:
            command += f" {additional_args}"
        
        command += f" {target} {service}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in hydra endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/john", methods=["POST"])
def john():
    """Execute john with the provided parameters."""
    try:
        params = request.json
        hash_file = params.get("hash_file", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        format_type = params.get("format", "")
        additional_args = params.get("additional_args", "")
        
        if not hash_file:
            logger.warning("John called without hash_file parameter")
            return jsonify({
                "error": "哈希文件参数是必需的"
            }), 400
        
        command = f"john"
        
        if format_type:
            command += f" --format={format_type}"
        
        if wordlist:
            command += f" --wordlist={wordlist}"
        
        if additional_args:
            command += f" {additional_args}"
        
        command += f" {hash_file}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in john endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/wpscan", methods=["POST"])
def wpscan():
    """Execute wpscan with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("WPScan called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400
        
        command = f"wpscan --url {url}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in wpscan endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/enum4linux", methods=["POST"])
def enum4linux():
    """Execute enum4linux with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "-a")
        
        if not target:
            logger.warning("Enum4linux called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400
        
        command = f"enum4linux {additional_args} {target}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in enum4linux endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500


@app.route("/api/tools/amass", methods=["POST"])
def amass():
    """Execute amass with the provided parameters."""
    try:
        params = request.json
        domain = params.get("domain", "")
        enum = params.get("enum", "d")
        additional_args = params.get("additional_args", "")
        
        if not domain:
            logger.warning("Amass called without domain parameter")
            return jsonify({
                "error": "Domain parameter is required"
            }), 400        
        
        command = f"amass enum -{enum} {domain}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in amass endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/nuclei", methods=["POST"])
def nuclei():
    """Execute nuclei with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        templates = params.get("templates", "")
        severity = params.get("severity", "")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("Nuclei called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400        
        
        command = f"nuclei -u {target}"
        
        if templates:
            command += f" -t {templates}"
        
        if severity:
            command += f" -severity {severity}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in nuclei endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/whatweb", methods=["POST"])
def whatweb():
    """Execute whatweb with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("WhatWeb called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400        
        
        command = f"whatweb {target}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in whatweb endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/ffuf", methods=["POST"])
def ffuf():
    """Execute ffuf with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/ffuf/common.txt")
        threads = params.get("threads", 10)
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("FFUF called without url parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400        
        
        command = f"ffuf -w {wordlist} -t {threads} -u {url}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in ffuf endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/masscan", methods=["POST"])
def masscan():
    """Execute masscan with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        ports = params.get("ports", "1-65535")
        rate = params.get("rate", 1000)
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("Masscan called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400        
        
        command = f"masscan {target} -p {ports} --rate {rate}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in masscan endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/gau", methods=["POST"])
def gau():
    """Execute gau with the provided parameters."""
    try:
        params = request.json
        domain = params.get("domain", "")
        additional_args = params.get("additional_args", "")
        
        if not domain:
            logger.warning("GAU called without domain parameter")
            return jsonify({
                "error": "Domain parameter is required"
            }), 400        
        
        command = f"gau {domain}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in gau endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/dnsx", methods=["POST"])
def dnsx():
    """Execute dnsx with the provided parameters."""
    try:
        params = request.json
        domain = params.get("domain", "")
        resolve = params.get("resolve", True)
        additional_args = params.get("additional_args", "")
        
        if not domain:
            logger.warning("DNSX called without domain parameter")
            return jsonify({
                "error": "Domain parameter is required"
            }), 400        
        
        command = f"dnsx -d {domain}"
        
        if resolve:
            command += " -resolve"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in dnsx endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/wafw00f", methods=["POST"])
def wafw00f():
    """Execute wafw00f with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("Wafw00f called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400        
        
        command = f"wafw00f {target}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in wafw00f endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/xsstrike", methods=["POST"])
def xsstrike():
    """Execute xsstrike with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("XSStrike called without url parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400        
        
        command = f"xsstrike -u {url}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in xsstrike endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/gospider", methods=["POST"])
def gospider():
    """Execute gospider with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        threads = params.get("threads", 5)
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("GoSpider called without url parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400        
        
        command = f"gospider -s {url} -t {threads}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in gospider endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/httpx", methods=["POST"])
def httpx():
    """Execute httpx with the provided parameters."""
    try:
        params = request.json
        target = params.get("target", "")
        probes = params.get("probes", "title,status-code")
        additional_args = params.get("additional_args", "")
        
        if not target:
            logger.warning("HTTPX called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400        
        
        command = f"httpx -u {target} -p {probes}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in httpx endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@app.route("/api/tools/arjun", methods=["POST"])
def arjun():
    """Execute arjun with the provided parameters."""
    try:
        params = request.json
        url = params.get("url", "")
        method = params.get("method", "GET")
        threads = params.get("threads", 5)
        additional_args = params.get("additional_args", "")
        
        if not url:
            logger.warning("Arjun called without url parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400        
        
        command = f"arjun -u {url} -m {method} -t {threads}"
        
        if additional_args:
            command += f" {additional_args}"
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in arjun endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

# Health check endpoint
@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint."""
    # Check if essential tools are installed
    essential_tools = ["nmap", "gobuster", "dirb", "nikto"]
    tools_status = {}
    
    for tool in essential_tools:
        try:
            result = execute_command(f"which {tool}")
            tools_status[tool] = result["success"]
        except:
            tools_status[tool] = False
    
    all_essential_tools_available = all(tools_status.values())
    
    return jsonify({
        "status": "healthy",
        "message": "Kali Linux工具API服务器正在运行",
        "tools_status": tools_status,
        "all_essential_tools_available": all_essential_tools_available
    })

@app.route("/mcp/capabilities", methods=["GET"]) 
def get_capabilities():
    """Return tool capabilities for MCP server."""
    capabilities = {
        "tools": [
            {"name": "nmap_scan", "description": "Execute an Nmap scan against a target."},
            {"name": "gobuster_scan", "description": "Execute Gobuster to find directories, DNS subdomains, or virtual hosts."},
            {"name": "nikto_scan", "description": "Execute Nikto web server scanner."},
            {"name": "sqlmap_scan", "description": "Execute SQLmap SQL injection scanner."},
            {"name": "metasploit_run", "description": "Execute a Metasploit module."},
            {"name": "hydra_attack", "description": "Execute Hydra password cracking tool."},
            {"name": "john_crack", "description": "Execute John the Ripper password cracker."},
            {"name": "wpscan_analyze", "description": "Execute WPScan WordPress vulnerability scanner."},
            {"name": "subfinder_scan", "description": "Execute subfinder for subdomain enumeration."},
            {"name": "dirsearch_scan", "description": "Execute dirsearch for directory scanning."},
            {"name": "amass_scan", "description": "Execute Amass for subdomain enumeration."},
            {"name": "nuclei_scan", "description": "Execute Nuclei for vulnerability scanning based on templates."},
            {"name": "whatweb_scan", "description": "Execute WhatWeb for website technology detection."},
            {"name": "ffuf_scan", "description": "Execute ffuf for web fuzzing."},
            {"name": "masscan_scan", "description": "Execute masscan for fast port scanning."},
            {"name": "gau_scan", "description": "Execute gau to fetch URLs from Wayback Machine, Common Crawl, and VirusTotal."},
            {"name": "dnsx_scan", "description": "Execute dnsx for DNS resolution and enumeration."},
            {"name": "wafw00f_scan", "description": "Execute wafw00f to detect web application firewalls."},
            {"name": "xsstrike_scan", "description": "Execute XSStrike for XSS vulnerability scanning."},
            {"name": "gospider_scan", "description": "Execute gospider for web spidering and URL discovery."},
            {"name": "httpx_scan", "description": "Execute httpx for HTTP probing and information gathering."},
            {"name": "arjun_scan", "description": "Execute arjun for parameter discovery in URLs."},
            {"name": "dirb_scan", "description": "Execute Dirb for directory brute-forcing."},
            {"name": "theHarvester_scan", "description": "Execute theHarvester for information gathering."},
            {"name": "cewl_scan", "description": "Execute Cewl to generate wordlists from web content."},
            {"name": "whois_scan", "description": "Execute whois domain lookup tool."},
            {"name": "dig_scan", "description": "Execute dig DNS query tool."},
            {"name": "enum4linux_scan", "description": "Execute Enum4linux Windows/Samba enumeration tool."},
            {"name": "server_health", "description": "Check the health status of the Kali API server."},
            {"name": "execute_command", "description": "Execute an arbitrary command on the Kali server."}
        ]
    }
    return jsonify(capabilities)

@app.route("/mcp/tools/kali_tools/<tool_name>", methods=["POST"]) 
def execute_tool(tool_name):
    """Direct tool execution endpoint for MCP server."""
    try:
        params = request.json
        logger.debug(f"Direct tool execution: {tool_name} with params: {params}")
        
        # Map tool name to API endpoint
        tool_endpoints = {
            "nmap_scan": "/api/tools/nmap",
            "gobuster_scan": "/api/tools/gobuster",
            "nikto_scan": "/api/tools/nikto",
            "sqlmap_scan": "/api/tools/sqlmap",
            "metasploit_run": "/api/tools/metasploit",
            "hydra_attack": "/api/tools/hydra",
            "john_crack": "/api/tools/john",
            "wpscan_analyze": "/api/tools/wpscan",
            "subfinder_scan": "/api/tools/subfinder",
            "dirsearch_scan": "/api/tools/dirsearch",
            "amass_scan": "/api/tools/amass",
            "nuclei_scan": "/api/tools/nuclei",
            "whatweb_scan": "/api/tools/whatweb",
            "ffuf_scan": "/api/tools/ffuf",
            "masscan_scan": "/api/tools/masscan",
            "gau_scan": "/api/tools/gau",
            "dnsx_scan": "/api/tools/dnsx",
            "wafw00f_scan": "/api/tools/wafw00f",
            "xsstrike_scan": "/api/tools/xsstrike",
            "gospider_scan": "/api/tools/gospider",
            "httpx_scan": "/api/tools/httpx",
            "arjun_scan": "/api/tools/arjun",
            "dirb_scan": "/api/tools/dirb",
            "theHarvester_scan": "/api/tools/theHarvester",
            "cewl_scan": "/api/tools/cewl",
            "whois_scan": "/api/tools/whois",
            "dig_scan": "/api/tools/dig",
            "enum4linux_scan": "/api/tools/enum4linux"
        }
        
        # Handle special tools that don't have direct API endpoints
        if tool_name == "execute_command":
            command = params.get("command", "")
            if not command:
                return jsonify({"error": "Command parameter is required"}), 400
            return generic_command()
        elif tool_name == "server_health":
            return health_check()
        elif tool_name in tool_endpoints:
            # Forward the request to the appropriate API endpoint
            from flask import current_app
            with current_app.test_request_context(tool_endpoints[tool_name], method='POST', json=params):
                # Create a new request context
                req = request._get_current_object()
                # Get the endpoint function based on the URL rule
                view_func = app.view_functions[app.url_map.bind('').match(tool_endpoints[tool_name])[0]]
                # Execute the view function
                response = view_func()
                return response
        else:
            logger.warning(f"Unsupported tool: {tool_name}")
            return jsonify({"error": f"Unsupported tool: {tool_name}"}), 404
    except Exception as e:
        logger.error(f"Error in direct tool execution: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {str(e)}"}), 500

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Run the Kali Linux API Server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--port", type=int, default=API_PORT, help=f"Port for the API server (default: {API_PORT})")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    
    # Set configuration from command line arguments
    if args.debug:
        DEBUG_MODE = True
        os.environ["DEBUG_MODE"] = "1"
        logger.setLevel(logging.DEBUG)
    
    if args.port != API_PORT:
        API_PORT = args.port
    
    logger.info(f"Starting Kali Linux Tools API Server on port {API_PORT}")
    app.run(host="0.0.0.0", port=API_PORT, debug=DEBUG_MODE)
