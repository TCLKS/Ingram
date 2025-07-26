"""数据流"""
import hashlib
import os
import time
from threading import Lock

from loguru import logger

from .utils import common
from .utils import timer


@common.singleton
class Data:

    def __init__(self, config):
        self.config = config
        self.create_time = timer.get_time_stamp()
        self.runned_time = 0
        self.taskid = hashlib.md5((self.config.in_file + self.config.out_dir).encode('utf-8')).hexdigest()

        self.total = 0
        self.done = 0
        self.found = 0

        self.total_lock = Lock()
        self.found_lock = Lock()
        self.done_lock = Lock()
        self.vulnerable_lock = Lock()
        self.not_vulneralbe_lock = Lock()

        self.preprocess()

    def _load_state_from_disk(self):
        """加载上次运行状态"""
        # done & found & run time
        state_file = os.path.join(self.config.out_dir, f".{self.taskid}")
        if os.path.exists(state_file):
            with open(state_file, 'r') as f:
                if line := f.readline().strip():
                    _done, _found, _runned_time = line.split(',')
                    self.done = int(_done)
                    self.found = int(_found)
                    self.runned_time = float(_runned_time)

    def _cal_total(self):
        """计算目标总数"""
        with open(self.config.in_file, 'r') as f:
            for line in f:
                if (strip_line := line.strip()) and not strip_line.startswith('#'):
                    self.add_total()

    def _generate_ip(self):
        with open(self.config.in_file, 'r') as f:
            for idx, line in enumerate(f):
                if (strip_line := line.strip()) and not strip_line.startswith('#'):
                    if idx < self.done:
                        continue
                    yield strip_line

    def preprocess(self):
        """预处理"""
        # 打开记录结果的文件
        self.vulnerable = open(os.path.join(self.config.out_dir, self.config.vulnerable), 'a')
        self.not_vulneralbe = open(os.path.join(self.config.out_dir, self.config.not_vulnerable), 'a')

        self._load_state_from_disk()

        self._cal_total()
        self.ip_generator = self._generate_ip()

    def add_total(self, item=1):
        if isinstance(item, int):
            with self.total_lock:
                self.total += item
        elif isinstance(item, list):
            with self.total_lock:
                self.total += sum(item)

    def add_found(self, item=1):
        if isinstance(item, int):
            with self.found_lock:
                self.found += item
        elif isinstance(item, list):
            with self.found_lock:
                self.found += sum(item)

    def add_done(self, item=1):
        if isinstance(item, int):
            with self.done_lock:
                self.done += item
        elif isinstance(item, list):
            with self.done_lock:
                self.done += sum(item)

    def add_vulnerable(self, item):
        with self.vulnerable_lock:
            self.vulnerable.writelines(','.join(item) + '\n')
            self.vulnerable.flush()

    def add_not_vulnerable(self, item):
        with self.not_vulneralbe_lock:
            self.not_vulneralbe.writelines(','.join(item) + '\n')
            self.not_vulneralbe.flush()

    def record_running_state(self):
        # 每隔 20 个记录一下当前运行状态
        if self.done % 20 == 0:
            with open(os.path.join(self.config.out_dir, f".{self.taskid}"), 'w') as f:
                f.write(f"{str(self.done)},{str(self.found)},{self.runned_time + timer.get_time_stamp() - self.create_time}")

    def __del__(self):
        try:  # if dont use try, sys.exit() may cause error
            self.record_running_state()
            self.vulnerable.close()
            self.not_vulneralbe.close()
        except Exception as e:
            logger.error(e)


@common.singleton
class SnapshotPipeline:

    def __init__(self, config):
        self.config = config
        self.snapshots_dir = os.path.join(self.config.out_dir, self.config.snapshots)
        self.done = len(os.listdir(self.snapshots_dir))

    def snapshot(self, exploit_func, results):
        """利用 poc 的 exploit 方法获取 results 处的资源"""
        if exploit_func(results):
            self.done += 1

    def get_done(self):
        return self.done
