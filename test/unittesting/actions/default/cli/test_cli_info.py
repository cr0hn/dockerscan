import click

from click.testing import CliRunner

from dockerscan.actions.default.cli import info

import dockerscan.actions.default.console


def _launch_dockerscan_in_console(blah, **kwargs):
    click.echo("ok")
    

def test_cli_info_runs_show_help():
    runner = CliRunner()
    result = runner.invoke(info)
    
    assert 'Usage: info [OPTIONS] ' in result.output


def test_cli_info_runs_ok():
    # Patch the launch of: launch_dockerscan_info_in_console
    dockerscan.actions.default.cli.launch_dockerscan_in_console = _launch_dockerscan_in_console
    
    runner = CliRunner()
    result = runner.invoke(info, ["aaaa"])
    
    assert 'ok' in result.output
