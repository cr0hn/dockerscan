import click

from .console import launch_dockerscan_scan_in_console


@click.command(help="Scan and search for Docker Registries")
@click.pass_context
@click.option("--scan")
@click.option("--shodan", "-S")
@click.option("--mrlooquer", "-S")
def discover(ctx, **kwargs):
    launch_dockerscan_scan_in_console(ctx.obj, **kwargs)
