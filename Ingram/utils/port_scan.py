"""端口扫描工具"""
import socket
import subprocess
from gevent import monkey
from typing import Iterable, List
from loguru import logger


def port_scan(ip: str, port: str, timeout: int = 1) -> bool:
    """使用 socket 的方式"""
    s = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if s.connect_ex((ip, int(port))) == 0:
            return True
    except Exception as e:
        logger.error(e)
    finally:
        s.close()
    return False


def go_port_scan(ip: str, ports: Iterable[str], go_bin: str, timeout: int = 1) -> List[int]:
    """使用 Go 程序一次性扫描多个端口

    params:
    - ip: ip 地址
    - ports: 端口列表
    - go_bin: Go 可执行文件路径
    - timeout: 超时时间（秒）
    """
    cmd = [go_bin, "-timeout", str(timeout), ip] + list(map(str, ports))
    run_func = monkey.get_original("subprocess", "run")
    try:
        res = run_func(cmd, capture_output=True, text=True, check=True)
    except Exception as e:
        logger.error(e)
        return []

    open_ports = []
    for line in res.stdout.splitlines():
        if ":" in line:
            try:
                open_ports.append(int(line.split(":")[1]))
            except ValueError:
                continue
    return open_ports