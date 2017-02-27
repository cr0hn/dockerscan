import tempfile

from .model import *
from .image_analyzer import *
from .docker_commands import *


def run_image_info_dockerscan(config: DockerImageInfoModel) -> DockerImageInfo:
    assert isinstance(config, DockerImageInfoModel)

    return get_docker_image_info(config.image_path,
                                 config.image_repository)


def run_image_extract_dockerscan(config: DockerImageExtractModel):
    assert isinstance(config, DockerImageExtractModel)

    extract_docker_image(config.image_path,
                         config.extract_path,
                         config.image_repository)


def run_image_analyze_dockerscan(config: DockerImageAnalyzeModel):
    assert isinstance(config, DockerImageAnalyzeModel)

    with tempfile.TemporaryDirectory() as tmp_dir:

        # Get docker info
        docker_info = get_docker_image_info(config.image_path,
                                            config.image_repository)

        # Extract docker data
        extract_docker_image(config.image_path,
                             tmp_dir,
                             config.image_repository)

        # Run the analysis
        analysis_results = analyze_docker_image(tmp_dir, docker_info)

    return analysis_results


__all__ = ("run_image_info_dockerscan",
           "run_image_extract_dockerscan",
           "run_image_analyze_dockerscan")
