### R2ELk
<p align="center">
<img src="https://i.imgur.com/RYc1qEU.png" /> 
<br />
<i>Metadata Binary Triage into ELK</i>
</p>

## About The Project
R2ELK leverages the Python bindings of [radare2's API](https://github.com/radareorg/radare2-r2pipe) 
to extract metadata from ELF and PE files.

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
* PDB file paths
* Base address
* Imports
* Exports

## Installation

### Dependencies
* [Requests](https://github.com/psf/requests)
* [r2pipe](https://github.com/radareorg/radare2-r2pipe)
```
sudo pip3 install -r requirements.txt
```

## Example Usage
*Note: The examples below are for direct ingestion into Elasticsearch not
Logstash". By default the index is "samples"*

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
./r2elk.py --file /bin/ls --rhost http://127.0.0.1 --rport 9200 --index testing
```
