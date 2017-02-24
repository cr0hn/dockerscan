from .model import *
from .docker_commands import *


def run_image_info_dockerscan(config: DockerImageInfoModel) -> DockerImageInfo:
    assert isinstance(config, DockerImageInfoModel)

    return get_docker_image_info(config.image_path)


def run_image_extract_dockerscan(config: DockerImageExtractModel):
    assert isinstance(config, DockerImageExtractModel)

    extract_docker_image(config.image_path,
                         config.extract_path)


__all__ = ("run_image_info_dockerscan", "run_image_extract_dockerscan")
