import os.path
import json
import hashlib
# import zipfile
# import tarfile
import click

from eark_validator import __version__
from eark_validator.infopacks.mets import MetsValidator
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
                        # sha1_hash = hashlib.sha1(f.read()).hexdigest()
                        sha1_hash = UTILS.sha1(file)
                    click.echo(f"{file} is a valid file with extension {extension} and SHA1: {sha1_hash} checksum.")
                    click.echo("Working...")
                    tmp_folder_name = sha1_hash
                    create_directory(tmp_folder_name)
                    metadata_file = open(os.path.join(tmp_folder_name, 'metadata.txt'), 'w')
                    metadata_file.write(f"File name: {os.path.basename(file)}\n")
                    metadata_file.write(f"File size: {os.path.getsize(file)} bytes\n")

                    # perform the validation
                    struct_details, schema_result, schema_errors, prof_names, schematron_result, prof_results = validate(file)
                    write_dict_to_file(dir(struct_details.errors), os.path.join(tmp_folder_name, 'struct_details.txt'))
                    write_dict_to_file(schema_result, os.path.join(tmp_folder_name, 'schema_result.txt'))
                    write_dict_to_file(schema_errors, os.path.join(tmp_folder_name, 'schema_errors.txt'))
                    write_dict_to_file(prof_names, os.path.join(tmp_folder_name, 'prof_names.txt'))
                    write_dict_to_file(schematron_result, os.path.join(tmp_folder_name, 'schematron_result.txt'))
                    write_dict_to_file(dir(prof_results), os.path.join(tmp_folder_name, 'prof_results.txt'))


                    # results_names = ["struct_details", "schema_result", "schema_errors", "prof_names", "schematron_result", "prof_results"]
                    # results_data = validate(file)
                    # for i, s in enumerate(results_names):
                    #     resultfilename = f"{s}.txt"
                    #     for k, v in vars(results_data[i]).items():
                    #         # write_dict_to_file(results_data[i], os.path.join(tmp_folder_name, resultfilename))
                    #         f = open(os.path.join(tmp_folder_name, resultfilename), 'w')
                    #         f.write(f"{k}: {v}\n")

                                        
                else:
                    click.echo(f"{file} has an invalid extension.")
            else:
                click.echo(f"{file} is not a valid file.")

def create_directory(directory_path):
    try:
        os.makedirs(directory_path)
    except FileExistsError:
        pass

def write_dict_to_file(d: dict, file_path: str):
    try:
        with open(file_path, "w") as f:
            json.dump(d, f)
    except:
         click.echo(f"Error: {file_path}")

def validate(to_validate):
    struct_details = IP.validate_package_structure(to_validate)
    # Schema and schematron validation to be factored out.
    # initialise schema and schematron validation structures
    schema_result = None
    prof_results = {}
    schema_errors = []
    # Schematron validation profile
    profile = ValidationProfile()
    # IF package is well formed then we can validate it.
    if struct_details.structure_status == IP.StructureStatus.WellFormed:
        # Schema based METS validation first
        validator = MetsValidator(struct_details.path)
        mets_path = os.path.join(struct_details.path, 'METS.xml')
        schema_result = validator.validate_mets(mets_path)
        # Now grab any errors
        schema_errors = validator.validation_errors
        if schema_result is True:
            profile.validate(mets_path)
            prof_results = profile.get_results()

    prof_names=ValidationProfile.NAMES
    schematron_result=profile.is_valid
    return struct_details, schema_result, schema_errors, prof_names, schematron_result, prof_results


def main():
    """Main Entry Point for CLI."""
    cli()

if __name__ == '__main__':
    cli()