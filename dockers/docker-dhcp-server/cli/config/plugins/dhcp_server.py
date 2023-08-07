import click
import utilities_common.cli as clicommon


@click.group(cls=clicommon.AbbreviationGroup, name="dhcp_server")
def dhcp_server():
    """config DHCP_SERVER information"""
    pass


def register(cli):
    cli.add_command(dhcp_server)


if __name__ == '__main__':
    dhcp_server()
