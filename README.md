# Cybersecurity Project 7

This repository contains the code for our project 7 for the Cybersecurity course.

The `cli.py` [file](./src/cra_demo_app/cli.py) is the original file provided by our prof.
The fixed version of the application will be found in a new version of this file with a fix version 1.0.1 of the package `cra_demo_app`.

### Running the application

Prior to running the application, make sure to install the required dependencies (uv is required, you can install it easily as described [here]((uv is required, you can install it using `pip install uv`))):
```bash
uv venv
uv sync
```

Then run the application using:
```bash
uv run cra_demo_app
```

### SBOM

The `sbom.json` file contains all dependencies of this project and was generated using:
```bash
cyclonedx-py environment > sbom.json
```

The folder `dtrack` contains a `docker-compose.yml` file to run a local instance of Dependency-Track for analyzing the SBOM.
It also contains another SBOM file, which is unrelated to our application, but was used to demonstrate the vulnerability-analysis feature of Dependency-Track.


### Tests

The `test` folder contains e2e-tests to verify the security of the (fixed) application.
To run the tests, use:
```bash
uv run pytest test/ -v
```