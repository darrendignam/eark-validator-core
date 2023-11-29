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

A sha1 checksum will be carried out, and a folder with that name will be filled with your validation results as JSON strings in .txt files.