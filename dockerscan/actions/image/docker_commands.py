"""
This file is based in the 'undocker' project, but modified for added new
features and Python 3 support.

Original undocker project:

https://github.com/larsks/undocker
"""

import os
import errno
import logging
import tarfile
import tempfile

try:
    import ujson as json
except ImportError:
    import json

from contextlib import closing, contextmanager
from dockerscan import DockerscanNotExitsError

from .model import DockerImageInfo

log = logging.getLogger("dockerscan")


# --------------------------------------------------------------------------
# Aux functions
# --------------------------------------------------------------------------
@contextmanager
def open_docker_image(image_path: str,
                      image_repository: str = ""):
    """
    This function is a context manager that allow to open a docker image and
    return their layers and the layers metadata.

    yields img, top_layers, layers, layers_metadata

    >>> with open_docker_image("~/images/nginx:latest") as (img, layers, meta):
        for layer_metadata in meta:
            print(layer_metadata)
    """
    tmp_image = os.path.basename(image_path)

    if ":" in tmp_image:
        image, tag = tmp_image.split(":", maxsplit=1)
    else:
        image, tag = tmp_image, "latest"

    #: Docker image layers and tags
    image_layers_tags = {}

    with tarfile.open(image_path, "r") as img:
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
            top_layers = repos_info[image][tag]
        except KeyError:
            try:
                image_and_repo = "{}/{}".format(image_repository,
                                                image)

                top_layers = repos_info[image_and_repo][tag]
            except KeyError:
                raise Exception(
                    'failed to find image {image} with tag {tag}'
                    ' (Command: "docker pull {image}:{tag}" will report '
                    'error)'.format(image=image,
                                    tag=tag))

        yield img, top_layers, image_layers_tags, \
              _find_metadata_in_layers(img, top_layers)


def _find_metadata_in_layers(img, id) -> dict:
    with closing(img.extractfile('%s/json' % id)) as fd:
        f_content = fd.read()
        if hasattr(f_content, "decode"):
            f_content = f_content.decode()
        yield json.loads(f_content)


def _find_layers(img, id):
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
        for layer in _find_layers(img, pid):
            yield layer


# --------------------------------------------------------------------------
# Public API
# --------------------------------------------------------------------------
def extract_docker_image(image_path: str,
                         extract_path: str,
                         image_repository: str):
    """Extract a docker image content to a path location"""
    if not os.path.exists(image_path):
        raise DockerscanNotExitsError("Docker image not exits at path: {}". \
                                      format(image_path))

    with open_docker_image(image_path,
                           image_repository) as (img, first_layer, _, _):
        layers = list(_find_layers(img, first_layer))

        if not os.path.isdir(extract_path):
            os.makedirs(extract_path)

        for layer_id in reversed(layers):
            log.debug('extracting layer %s', layer_id)

            with tarfile.open(fileobj=img.extractfile('%s/layer.tar' %
                                                              layer_id),
                              errorlevel=0,
                              dereference=True) as layer:

                layer.extractall(path=extract_path)

                log.debug('processing whiteouts')
                for member in layer.getmembers():
                    path = member.path
                    if path.startswith('.wh.') or '/.wh.' in path:
                        if path.startswith('.wh.'):
                            newpath = path[4:]
                        else:
                            newpath = path.replace('/.wh.', '/')

                        try:
                            log.debug('removing path %s', newpath)
                            os.unlink(path)
                            os.unlink(newpath)
                        except OSError as err:
                            if err.errno != errno.ENOENT:
                                raise


def get_docker_image_info(image_path: str,
                          image_repository: str) -> DockerImageInfo:

    results = DockerImageInfo()

    with open_docker_image(image_path,
                           image_repository) as (_, _, _, layers_meta):
        for layer in layers_meta:
            results.add_layer_info(layer)

    return results


__all__ = ("open_docker_image", "get_docker_image_info",
           "extract_docker_image")