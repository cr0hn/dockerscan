from .model import *
from .libs.undocker import extract_docker_image, UnDockerConfig


def run_analyze_dockerscan(config: DockerImageModel) -> DockerImageInfo:
    assert isinstance(config, DockerImageModel)

    un_docker_config = UnDockerConfig(config.image_path)

    return extract_docker_image(un_docker_config)


__all__ = ("run_analyze_dockerscan", )
