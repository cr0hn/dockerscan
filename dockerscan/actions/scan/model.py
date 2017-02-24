
from dockerscan import SharedConfig, String


class DockerScanModel(SharedConfig):
    scan = String()
    shodan = String()
    mrlooquer = String()

__all__ = ("DockerScanModel",)
