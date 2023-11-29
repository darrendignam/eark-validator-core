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
                    write_data_to_file(format_struct(struct_details), os.path.join(tmp_folder_name, f'structure_checks.{struct_details.structure_status.name}.txt'))
                    write_data_to_file(format_profile_results(prof_names,prof_results), os.path.join(tmp_folder_name, f'schematron_validation.{schematron_result}.txt'))
                    write_data_to_file(schema_errors, os.path.join(tmp_folder_name, f'schema_validation.{schema_result}.txt'))
                
                else:
                    click.echo(f"{file} has an invalid extension.")
            else:
                click.echo(f"{file} is not a valid file.")


def format_struct(struct: IP.PackageDetails):
    result_dict = {}
    result_dict["errors"] = []
    for error in struct.errors:
        result_dict["errors"].append({"severity": error.severity.name, "message": error.message, "sub_message": error.sub_message, "rule": f"https://earkcsip.dilcis.eu/#{ error.rule_id }" }) 
    return result_dict

def format_profile_results(names, results):
    result_dict = { "root": {"title": "METS Root", "is_valid": results["root"].is_valid},
                    "hdr": {"title": "METS Header", "is_valid": results["hdr"].is_valid},
                    "amd": {"title": "Adminstrative Metadata", "is_valid": results["amd"].is_valid},
                    "file": {"title": "File Section", "is_valid": results["file"].is_valid},
                    "structmap": {"title": "Structural Map", "is_valid": results["structmap"].is_valid}  }

    return result_dict

def format_schema_results(schema_results):
    result_dict = []
    for error in schema_results:
        result_dict.append({ "error": error.msg })
    return result_dict



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

def write_data_to_file(data, file_path):
    with open(file_path, "w") as f:
        if isinstance(data, list):
            for item in data:
                f.write(json.dumps(item) + "\n")
        elif isinstance(data, dict):
            f.write(json.dumps(data) + "\n")
        elif isinstance(data, set):
            for item in data:
                f.write(json.dumps(item) + "\n")
        else:
            raise ValueError(f"Data must be a list, dictionary, or set {file_path}")

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