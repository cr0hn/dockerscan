from dockerscan import SharedConfig, String


class DockerImageInfoModifyTrojanizeModel(SharedConfig):
    image_path = String()
    image_repository = String(default="")
    output_image = String(default="")


__all__ = ("DockerImageInfoModifyTrojanizeModel", )
