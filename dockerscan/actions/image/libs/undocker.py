"""
This file is based in the 'undocker' project, but modified for added new
features and Python 3 support
"""

import os
import json
import errno
import logging
import tarfile
import tempfile

from contextlib import closing

from ..model import DockerImageInfo

log = logging.getLogger(__name__)


class UnDockerConfig:

    def __init__(self,
                 image_path: str,
                 extract: bool = False,
                 extract_path: str = None,
                 ignore_errors: bool = False):
        self.extract = extract
        self.image_path = os.path.abspath(image_path)
        self.extract_path = extract_path or os.path.join(os.getcwd(), "out")
        self.ignore_errors = ignore_errors

        if not os.path.exists(self.image_path):
            raise FileExistsError("Docker image not exits at path: {}". \
                                  format(self.image_path))

        tmp_image = os.path.basename(self.image_path)

        if ":" in tmp_image:
            self.image, self.tag = tmp_image.split(":", maxsplit=1)
        else:
            self.image, self.tag = tmp_image, "latest"


def find_metadata_in_layers(img, id) -> dict:
    with closing(img.extractfile('%s/json' % id)) as fd:
        f_content = fd.read()
        if hasattr(f_content, "decode"):
            f_content = f_content.decode()
        yield json.loads(f_content)


def find_layers(img, id):
    with closing(img.extractfile('%s/json' % id)) as fd:
        f_content = fd.read()
        if hasattr(f_content, "decode"):
            f_content = f_content.decode()
        info = json.loads(f_content)

    log.debug('layer = %s', id)
    for k in ['os', 'architecture', 'author', 'created']:
        if k in info:
            log.debug('%s = %s', k, info[k])

    yield id

    if 'parent' in info:
        pid = info['parent']
        for layer in find_layers(img, pid):
            yield layer


def extract_docker_image(config: UnDockerConfig) -> DockerImageInfo:

    results = DockerImageInfo()

    #: Docker image layers and tags
    image_layers_tags = {}

    with tempfile.NamedTemporaryFile() as fd:
        # If image passed as a parameter, read it
        fd.write(open(config.image_path, "rb").read())

        with tarfile.open(config.image_path, "r") as img:
            # with tarfile.TarFile(fileobj=fd) as img:
            repos = img.extractfile('repositories')

            repo_content = repos.read()
            # If data are bytes, transform to str. JSON only accept str.
            if hasattr(repo_content, "decode"):
                repo_content = repo_content.decode()

            # Clean repo content
            repo_content = repo_content.replace("\n", "").replace("\r", "")

            repos_info = json.loads(repo_content)

            for name, tags in repos_info.items():
                image_layers_tags[name] = " ".join(tags)

            try:
                top = repos_info[config.image][config.tag]
            except KeyError:
                raise Exception(
                    'failed to find image {image} with tag {tag}'
                    ' (Command: "docker pull {image}:{tag}" will report '
                    'error)'.format(image=config.image,
                                    tag=config.tag))

            #
            # Extract metadata content
            #
            for layer_metadata in find_metadata_in_layers(img, top):
                results.add_layer_info(layer_metadata)

            #
            # Extract layers content
            #
            if config.extract:

                log.info('extracting image %s (%s)', config.image, top)
                layers = list(find_layers(img, top))

                if not os.path.isdir(config.extract_path):
                    os.makedirs(config.extract_path)

                for layer_id in reversed(layers):
                    log.info('extracting layer %s', layer_id)

                    with tarfile.open(fileobj=img.extractfile(
                                    '%s/layer.tar' % layer_id)) as layer:

                        layer.extractall(path=config.extract_path)

                        log.info('processing whiteouts')
                        for member in layer.getmembers():
                            path = member.path
                            if path.startswith('.wh.') or '/.wh.' in path:
                                if path.startswith('.wh.'):
                                    newpath = path[4:]
                                else:
                                    newpath = path.replace('/.wh.', '/')

                                try:
                                    log.info('removing path %s', newpath)
                                    os.unlink(path)
                                    os.unlink(newpath)
                                except OSError as err:
                                    if err.errno != errno.ENOENT:
                                        raise

    return results
