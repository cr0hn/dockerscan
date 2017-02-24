# -*- coding: utf-8 -*-

from booby import *


class SharedConfig(Model):
    verbosity = Integer(default=0)
    # worker = String(choices=['process', 'threads'])
    # concurrency = Integer()
    timeout = Integer(default=10)
