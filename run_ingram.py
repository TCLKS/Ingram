#! /usr/bin/env python3
# coding  : utf-8
# @Author : Jor<jorhelp@qq.com>
# @Date   : Wed Apr 20 00:17:30 HKT 2022
# @Desc   : Webcam vulnerability scanning tool

#=================== 需放置于最开头 ====================
import warnings
warnings.filterwarnings("ignore")
#======================================================

import os
import sys

from loguru import logger

from Ingram import get_config
from Ingram import Core
from Ingram.utils import color
from Ingram.utils import get_parse
from Ingram.utils import log
from Ingram.utils import logo

sys.stderr = open(os.devnull, 'w')
def run():
    try:
        # logo
        for icon, font in zip(*logo):
            print(f"{color.yellow(icon, 'bright')}  {color.magenta(font, 'bright')}")

        # config
        config = get_config(get_parse())
        if not os.path.isdir(config.out_dir):
            os.mkdir(config.out_dir)
        snapshots_path = os.path.join(config.out_dir, config.snapshots)
        if not os.path.isdir(snapshots_path):
            os.mkdir(snapshots_path)
        if not os.path.isfile(config.in_file):
            print(f"{color.red('the input file')} {color.yellow(config.in_file)} {color.red('does not exists!')}")
            sys.exit()

        # log 配置
        log.config_logger(os.path.join(config.out_dir, config.log), config.debug)

        # 执行任务
        Core(config).run()

    except KeyboardInterrupt:
        logger.warning('Ctrl + c was pressed')
        sys.exit()

    except Exception as e:
        logger.error(e)
        print(f"{color.red('error occurred, see the')} {color.yellow(config.log)} "
              f"{color.red('for more information.')}")
        sys.exit()


if __name__ == '__main__':
    run()
