### R2ELk
<p align="center">
<img src="https://i.imgur.com/RYc1qEU.png" /> 
<br />
<i>Metadata Binary Triage into ELK</i>
</p>

## About The Project
R2ELK leverages the Python bindings of [radare2's API](https://github.com/radareorg/radare2-r2pipe) 
to extract metadata from ELF and PE files and The [official](https://github.com/Yara-Rules/rules/tree/master) 
YARA rule repo as a submodule for matching.

Data that is attempted to be extracted/identified is as follows:
* File name 
* File format
* MD5 hash
* SHA1 hash
* Architecture
* Binary size
* Programming language Used (*identified by r2*)
* Compiler info
* Compiled time
* Stripped
* Static
* Signed
* Strings
* PDB file paths
* Base address
* Imports
* Exports
* Yara Rule matching

## Installation

### Dependencies
* [Requests](https://github.com/psf/requests)
* [r2pipe](https://github.com/radareorg/radare2-r2pipe)
* [yara-python](https://github.com/VirusTotal/yara-python)
```
sudo pip3 install -r requirements.txt
```

*If using  yara rules for sample tagging*: ```git submodule update --recursive```

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

* Run yara file against binary
```
./r2elk.py -f /bin/ls --yara ./rules/malware/malware_samples.yar 
```

### Indexing A Field Per-Function 
If you're interested in having a single field per import/export opposed to a
single field with a comma separated string of imports/exports, modify the
[run_triage](https://github.com/jaredestroud/r2elk/blob/master/r2elk.py#L258) function to call ``` self.get_import_fields() ``` and
``` self.get_export_fields() ```

Example:
```

    def run_triage(self):
        '''
        Name: run_triage
        Purpose: Perform metadata triage of binaries.
        Paramters: N/A
        Return: JSON dump of metadata info.
        '''
        self.get_metadata()
        self.get_imports_fields()
        self.get_exports_fields()
        self.get_hashes()
        self.__r2_close__() # Close r2 pipe object.
        return json.dumps(self.metadata)
```



### Troubleshooting
* Do you have appropriate permission for reading files in specific directory?
* Symlinks are not followed.
