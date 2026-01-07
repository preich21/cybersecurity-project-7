# Cybersecurity Project 7

This repository contains the code for our project 7 for the Cybersecurity course.

The `insecure-application.py` file is the original file provided by our prof.
The `fixed-application.py` file contains all the fixes we made to harden the application.


### Running the application

Prior to running the application, make sure to install the required dependencies:
```bash
pip install -r requirements.txt
```

Then run the application using:
```bash
python fixed-application.py
```


### SBOM

The `sbom.json` file contains all dependencies of this project and was generated using:
```bash
cyclonedx-py requirements > sbom.json
```

The folder `dtrack` contains a `docker-compose.yml` file to run a local instance of Dependency-Track for analyzing the SBOM.
It also contains another SBOM file, which is unrelated to our application, but was used to demonstrate the vulnerability-analysis feature of Dependency-Track.


### Tests

The `test` folder contains e2e-tests to verify the security of the fixed application.
To run the tests, use:
```bash
pytest test/ -v
```