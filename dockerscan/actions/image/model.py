from collections import defaultdict

from dockerscan import SharedConfig, String


class DockerImageInfoModel(SharedConfig):
    image_path = String()


class DockerImageExtractModel(SharedConfig):
    image_path = String()
    extract_path = String()


class DockerImageInfo:

    def __init__(self):
        self.author = ""
        self.host_name = ""
        self.entry_point = ""
        self.working_dir = ""
        self.created_date = ""
        self.docker_version = ""
        self.cmd = ""
        self.labels = []
        self.environment = []

        #: dict - { PORT_NO: ["TCP", "UDP"]}
        #: dict - { PORT_NO: ["TCP"]}
        self.exposed_ports = defaultdict(set)

    def add_layer_info(self, layer_info: dict):
        # Get container config
        # container_config = layer_info.get("container_config", None)
        container_config = layer_info.get("config", None)

        if container_config:
            basic_info = {
                "Hostname": "host_name",
                "WorkingDir": "working_dir",
                "Entrypoint": "entry_point"
            }
            list_info = {
                "Env": "environment",
                "Labels": "labels"
            }

            for json_prop, class_prop in basic_info.items():
                json_value = container_config.get(json_prop)
                if json_value:
                    setattr(self, class_prop, json_value)

            for json_prop, class_prop in list_info.items():
                json_value = container_config.get(json_prop)
                if json_value:
                    class_value = getattr(self, class_prop)
                    class_value.extend(json_value)

            if "Cmd" in container_config:
                # Get only the Cmd Command of the last layer
                if "container" in layer_info:
                    self.cmd = " ".join(container_config.get("Cmd"))

            # Add exposed ports
            if "ExposedPorts" in container_config:
                for port in container_config.get("ExposedPorts").keys():
                    port, proto = port.split("/")

                    self.exposed_ports[port].add(proto)

        # Only storage the date for the last layer. And only the last layer
        # contains "container" property
        if "container" in layer_info:
            self.created_date = layer_info.get("created")

        if "author" in layer_info:
            self.author = layer_info.get("author")

        if "docker_version" in layer_info:
            self.docker_version = layer_info.get("docker_version")


__all__ = ("DockerImageInfoModel", "DockerImageInfo", "DockerImageExtractModel")
