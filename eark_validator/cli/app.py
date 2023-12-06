import os.path
import json as jsonformatter
import dicttoxml
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
# @click.option("--recursive", "-r", default=True, help="When analysing an information package recurse into representations.")
# @click.option("--checksum", "-c", default=False, help="Calculate and verify file checksums in packages.")
# @click.option("--verbose", "-v", default=False, help="Report results in verbose format")
@click.option("--json", default=True, help="Report results in JSON format")
@click.option("--xml", default=False, help="Report results in XML format")
@click.option("--hardcopy", default=False, help="Report results as files on the filesystem")
@click.argument('files', nargs=-1)
# @click.argument('file', type=click.Path(exists=True))
@click.pass_context
def cli(ctx, json, xml, hardcopy, files):
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
                    # Create basic metadata
                    filename = os.path.basename(file)
                    filepath = os.path.dirname(file)
                    filesize = os.path.getsize(file)
                    sha1_hash = UTILS.sha1(file)

                    validation_result = {}
                    validation_result["metadata"] = { "filename":filename, "filepath":filepath, "filesize":filesize, "sha1":sha1_hash }

                    # perform the validation
                    struct_dict, prof_results_dict, mets_results_dict, struct_details, schema_result, schema_errors, prof_names, schematron_result, prof_results = validate(file)
                    
                    # Process Results
                    validation_result["structure"] = struct_dict
                    validation_result["profile"] = prof_results_dict
                    validation_result["mets"] = mets_results_dict

                    if xml:
                        click.echo( dicttoxml.dicttoxml(validation_result, return_bytes=False) )
                        if hardcopy:
                            hardcopy_file(filename,extension,sha1_hash, validation_result, False, "xml")
                    elif json:
                        click.echo( jsonformatter.dumps(validation_result) )
                        if hardcopy:
                            hardcopy_file(filename,extension,sha1_hash, validation_result, False, "json")
                    elif hardcopy:
                        hardcopy_file(filename,extension,sha1_hash, validation_result, True, "xml")
                
                else:
                    click.echo(f"{file} has an invalid extension.")
            else:
                click.echo(f"{file} is not a valid file.")

def hardcopy_file(filename, extension, sha1_hash, data, verbose=False, format="xml"):
    if verbose:
        click.echo(f"{file} is a valid file with extension {extension} and SHA1: {sha1_hash} checksum.")
        click.echo("Working...")
    tmp_folder_name = sha1_hash
    create_directory(tmp_folder_name)
    if format=='xml':
        write_data_to_file_xml(data, os.path.join(tmp_folder_name, f'ip_validator.{filename}.xml'))
    else:
        write_data_to_file_json(data, os.path.join(tmp_folder_name, f'ip_validator.{filename}.json'))


def create_directory(directory_path):
    try:
        os.makedirs(directory_path)
    except FileExistsError:
        pass

def write_dict_to_file(d: dict, file_path: str):
    try:
        with open(file_path, "w") as f:
            jsonformatter.dump(d, f)
    except:
         click.echo(f"Error: {file_path}")

def write_data_to_file_json(data, file_path):
    with open(file_path, "w") as f:
        if isinstance(data, list):
            for item in data:
                f.write(jsonformatter.dumps(item) + "\n")
        elif isinstance(data, dict):
            f.write(jsonformatter.dumps(data) + "\n")
        elif isinstance(data, set):
            for item in data:
                f.write(jsonformatter.dumps(item) + "\n")
        else:
            raise ValueError(f"Data must be a list, dictionary, or set {file_path}")
        
def write_data_to_file_xml(data, file_path):
    with open(file_path, "w") as f:
        f.write(dicttoxml.dicttoxml(data, return_bytes=False))

def validate(to_validate):
    struct_dict, struct_details = IP.validate_package_structure_dict(to_validate)
    # Schema and schematron validation to be factored out.
    # initialise schema and schematron validation structures
    schema_result = None
    prof_results = {}
    prof_results_dict = {}
    schema_errors = []
    # Schematron validation profile
    profile = ValidationProfile()
    # IF package is well formed then we can validate it.
    if struct_details.structure_status == IP.StructureStatus.WellFormed:
        # Schema based METS validation first
        validator = MetsValidator(struct_details.path)
        mets_path = os.path.join(struct_details.path, 'METS.xml')
        schema_result = validator.validate_mets(mets_path)
        mets_results_dict = validator.get_results_dict()
        # Now grab any errors
        schema_errors = validator.validation_errors
        if schema_result is True:
            profile.validate(mets_path)
            prof_results = profile.get_results()
            prof_results_dict = profile.get_results_dict()

    prof_names=ValidationProfile.NAMES
    schematron_result=profile.is_valid
    return struct_dict, prof_results_dict, mets_results_dict, struct_details, schema_result, schema_errors, prof_names, schematron_result, prof_results


def main():
    """Main Entry Point for CLI."""
    cli()

if __name__ == '__main__':
    cli()