#!/usr/bin/env python

"""
//  -------------------------------------------------------------
//  author        Giga
//  project       qeeqbox/vulnerable-web-app
//  email         gigaqeeq@gmail.com
//  description   app.py (CLI)
//  licensee      AGPL-3.0
//  -------------------------------------------------------------
//  contributors list qeeqbox/vulnerable-web-app/graphs/contributors
//  -------------------------------------------------------------
"""

from psutil import boot_time,cpu_count, cpu_freq, virtual_memory, cpu_percent, disk_partitions, disk_usage, net_if_addrs, net_io_counters, process_iter
from datetime import datetime
from contextlib import suppress
from platform import uname

info =  []

info.extend([f"{attr}: {value}" for attr,value in zip(['System', 'Node', 'Release', 'Version', 'Machine'], uname())])

info.extend([f"Boot Time: {datetime.fromtimestamp(boot_time())}",
            f"Physical cores: {cpu_count(logical=False)}",
            f"Logical cores: {cpu_count(logical=True)}",
            f"Current CPU frequency: {cpu_freq().current}Mhz",
            f"Minimum CPU frequency: {cpu_freq().min}Mhz",
            f"Maximum CPU frequency: {cpu_freq().max}Mhz",
            f"Total Memory: {virtual_memory().total/(1024.0**3):.2f}GB",
            f"Available Memory: {virtual_memory().available/(1024.0**3):.2f}GB",
            f"Total Used: {virtual_memory().used/(1024.0**3):.2f}GB",
            f"Percentage: {virtual_memory().percent}%"])

for partition in disk_partitions():
    with suppress(Exception):
        info.append(f"Device: {partition.device}, File system type: {partition.fstype}, Mountpoint: {partition.mountpoint}, Total Space: {disk_usage(partition.mountpoint).total/(1024**3):.2f}GB, Used Space: {disk_usage(partition.mountpoint).used/(1024**3):.2f}GB, Free Space: {disk_usage(partition.mountpoint).free/(1024**3):.2f}GB, Percentage Used: {disk_usage(partition.mountpoint).percent}%")

for name, addresses in net_if_addrs().items():
    for address in addresses:
        with suppress(Exception):
            info.append(f"Interface {name}, Family: {address.family}, Address: {address.address}, Netmask: {address.netmask}, Broadcast: {address.broadcast}, PTP: {address.ptp}")

info.extend([f"Total Network Bytes Sent: {net_io_counters().bytes_sent/(1024**3):.2f}GB",
             f"Total Network Bytes Received: {net_io_counters().bytes_recv/(1024**3):.2f}GB"])

for process in process_iter(['pid', 'name', 'memory_percent']):
    with suppress(Exception):
        info.append(f"PID: {process.info['pid']}, Name: {process.info['name']}, Memory: {process.info['memory_percent']:.2f}%")

for line in info:
    print(line)
