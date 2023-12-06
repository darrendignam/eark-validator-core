Set up a local virtual environment:

```shell
virtualenv -p python3 venv
source venv/bin/activate
```

```shell
python -m build
pip install .
```

To use the cli validator:

```shell
ip_validate [/path/to/file.tar]
```
When invoked like this, the application will output a JSON formatted string to the STDOUT terminal as the default response. 
For other formats or more fine grained output please refer to the help:

```shell
Options:
  --version           Show the version and exit.
  --json BOOLEAN      Report results in JSON format
  --xml BOOLEAN       Report results in XML format
  --hardcopy BOOLEAN  Report results as files on the filesystem
  --help              Show this message and exit.
```

If you choose to keep a 'hardcopy' then a results file will be created 
A sha1 checksum will be carried out, and a folder with that name will be filled with your validation results as JSON or XML strings in .txt files.