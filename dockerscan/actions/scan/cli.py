import click

# from .console import launch_dockerscan_scan_in_console


@click.command(help="Search for Open Docker Registries (still not avaible)")
@click.pass_context
# @click.option("--scan")
# @click.option("--shodan", "-S")
# @click.option("--mrlooquer", "-M")
def discover(ctx, **kwargs):
    # launch_dockerscan_scan_in_console(ctx.obj, **kwargs)
    pass
