import click


from .model import DockerImageModel
from .console import launch_dockerscan_image_in_console
from ..helpers import check_console_input_config


@click.command(help="Analyze a docker image")
@click.pass_context
@click.argument("image_path")
def image(ctx, **kwargs):
    config = DockerImageModel(**ctx.obj, **kwargs)

    # Check if valid
    if check_console_input_config(config):
        launch_dockerscan_image_in_console(config)
