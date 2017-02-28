from dockerscan import SharedConfig, String


class DockerImageInfoModifyTrojanizeModel(SharedConfig):
    image_path = String()
    image_repository = String(default="")
    remote_addr = String()
    remote_port = String(default="2222")
    output_image = String(default="")


__all__ = ("DockerImageInfoModifyTrojanizeModel", )
