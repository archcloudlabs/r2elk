### R2ELk
<p align="center">
<!-- <img width="264" height="61" src="https://i.imgur.com/EZvIdl2.png"> --!>
<img src="https://i.imgur.com/EZvIdl2.png" /> 
<br />
<i>Metadata Binary Triage into ELK</i>
</p>

## About The Project
R2ELK leverages the Python bindings of [radare2's API](https://github.com/radareorg/radare2-r2pipe) 
to extract metadata from ELK and PE files.

Data that is attempted to be extracted is as follows:
* File name 
* File format
* MD5 hash
* SHA1 hash
* Architecture
* Binary size
* Programming language Used
* Compiler info
* Compiled time
* Stripped
* Static
* Signed
* PDB files
* Base address
* Imports
* Exports

## Installation

### Dependencies
* Python requests
* r2pipe
```
pip install -r requirements.txt
```

## Example Usage
* Get metadata about a single binary:
```
/r2elk.py --file /bin/ls | python -m json.tool
```

* Get metadata from a directory of binaries:
```
/r2elk.py --directory /bin/ 
```

* Get metadata from a directory of binaries and POST to Elastic server:
```
/r2elk.py --directory /bin/ --rhost 127.0.0.1 --rport 9200
```
