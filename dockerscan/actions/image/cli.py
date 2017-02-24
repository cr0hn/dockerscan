import click


from .model import *
from .console import *
from ..helpers import check_console_input_config


@click.group(help="Docker images commands")
@click.pass_context
def image(ctx, **kwargs):
    pass


@image.command(help="get docker image information")
@click.pass_context
@click.argument("image_path")
def info(ctx, **kwargs):
    config = DockerImageInfoModel(**ctx.obj, **kwargs)

    # Check if valid
    if check_console_input_config(config):
        launch_dockerscan_image_info_in_console(config)


@image.command(help="extract docker image content")
@click.pass_context
@click.argument("image_path")
@click.argument("extract_path")
def extract(ctx, **kwargs):
    config = DockerImageExtractModel(**ctx.obj, **kwargs)

    # Check if valid
    if check_console_input_config(config):
        launch_dockerscan_image_extract_in_console(config)
