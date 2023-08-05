import click
import utilities_common.cli as clicommon


@click.group(cls=clicommon.AliasedGroup, name="dhcp_server")
def dhcp_server():
    """show DHCP_SERVER information"""
    pass


def register(cli):
    cli.add_command(dhcp_server)
