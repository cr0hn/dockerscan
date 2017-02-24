from .model import *


def run_scan_dockerscan(config: DockerScanModel):
    assert isinstance(config, DockerScanModel)

    print(config.scan)


__all__ = ("run_scan_dockerscan",)
