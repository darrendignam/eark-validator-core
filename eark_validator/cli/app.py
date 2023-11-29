from eark_validator import __version__
import os.path
import zipfile
import tarfile
import click
import hashlib

from eark_validator.infopacks.rules import ValidationProfile
import eark_validator.infopacks.information_package as IP
import eark_validator.utils as UTILS

ALLOWED_EXTENSIONS = {'zip', 'tar', 'gz', 'gzip'}

@click.command()
@click.version_option(__version__)
@click.option("--recursive", "-r", default=True, help="When analysing an information package recurse into representations.")
@click.option("--checksum", "-c", default=False, help="Calculate and verify file checksums in packages.")
@click.option("--verbose", "-v", default=False, help="Report results in verbose format")
@click.argument('files', nargs=-1)
# @click.argument('file', type=click.Path(exists=True))
@click.pass_context
def cli(ctx, recursive, checksum, verbose, files):
    """E-ARK Information Package validation (ip-check).
ip-check is a command-line tool to analyse and validate the structure and
metadata against the E-ARK Information Package specifications.
It is designed for simple integration into automated work-flows."""

    if len(files) == 0:
        click.echo(click.get_current_context().get_help())
    else:
        for file in files:
            if os.path.isfile(file):
                extension = os.path.splitext(file)[-1][1:].lower()
                if extension in ALLOWED_EXTENSIONS:
                    with open(file, 'rb') as f:
                        md5_hash = hashlib.md5(f.read()).hexdigest()
                        sha1_hash = hashlib.sha1(f.read()).hexdigest()
                    click.echo(f"{file} is a valid file with extension {extension} and MD5: {sha1_hash} checksum.")
                    click.echo("Working...")
                else:
                    click.echo(f"{file} has an invalid extension.")
            else:
                click.echo(f"{file} is not a valid file.")




def main():
    """Main Entry Point for CLI."""
    cli()

if __name__ == '__main__':
    cli()