#!/usr/bin/python3
"""
    R2ELK is a Python binary parsing utility that leverages the Radare2 Python
    API. Metadata extracted from the binaries is then presented to the end user
    in JSON format.
"""
try:
    import sys
    import os
    from os import access, R_OK
    import errno
    import json
    import argparse
    from datetime import datetime
    from stat import S_ISREG
    import r2pipe
    import requests

except ImportError as import_err:
    print("[!] Missing package %s." % str(import_err))
    sys.exit(1)


class Utils():
    '''
    Helper utilities to aid in loading binaries for triage.
    '''

    def list_files(self, directory):
        '''
        Name: list_files
        Purpose: List all files within a directory and run R2 triage methods.
                 This method will not follow symlinks.
                 https://docs.python.org/3.7/library/stat.html
        Return: List of files within a directory.
        '''
        normal_files = []
        for filename in os.listdir(directory):
            file_path = os.path.join(directory, filename)
            try:
                file_info = os.lstat(file_path)
            except EnvironmentError:
                continue
            else:
                # Check for non-symlink files and readable files.
                if S_ISREG(file_info.st_mode) and access(file_path, R_OK):
                    normal_files.append(file_path)
                else:
                    print("[*] Skipping processing of %s" % str(file_path))
        return normal_files


    def elk_post(self, data, rhost, rport):
        '''
        Name: elk_post
        Purpose: Post JSON data to Elastic endpoint (could also be logstash)
        Parameters: [rhost] remote Elasticserver to post to.
            [rport] remote port that Elastic is running on.
        Return: boolean based on success or failure of HTTP POST.
        '''
        headers = {"Content-Type" : "application/json"}
        try:
            req = requests.post(rhost+":"+rport, headers=headers, body=data)
            return True
        except requests.exceptions.RequestException as err:
            print("[!] Error posting data!\n\\t %s" % str(err))
            return False

class Triage():
    '''
    Perform binary metadata analysis via R2 and cleanup output for ES ingestion.
    '''

    def __init__(self, binary):
        self.metadata = {} # Dict populated by private functions.
        self.binary = binary
        self.r2obj = self.__r2_load__()

    def __r2_load__(self):
        '''
        Name: __r2_load__
        Purpose: Create a r2 instance for triage object to use.
        Return: r2pipe object.
        '''
        try:
            return r2pipe.open(self.binary)
        except IOException:
            print("[!] Error opening file %s." % str(self.binary))
            sys.exit(1)

    def __r2_close__(self):
        '''
        Name: close radare2 handle
        Parameters: N/A
        Return: N/A
        '''
        self.r2obj.quit()

    def __get_hashes__(self):
        '''
        Name: __get__hashes__
        Purpose: Leverage r2pipe to get MD5 and SHA1 hash
        Return: N/A, populate self.metadata dict.
        '''
        try:
            self.metadata["md5"] = self.r2obj.cmdj("itj").get("md5")
            self.metadata["sha1"] = self.r2obj.cmdj("itj").get("sha1")
        except:
            self.metadata["md5"] = "Error getting MD5 for file"
            self.metadata["sha1"] = "Error getting SHA1 for file"


    def __check_parsable_file__(self, ftype):
        '''
        Name: __check_parsable_file__
        Purpose: Check that a valid binary file is trying to be parsed.
        Return: Boolean indicating whether or not its a valid file type.
        '''
        valid_types = ["pe", "elf", "elf64", "pe64", "pe64+", "pe32+", "pe+"]
        if ftype not in valid_types:
            return False
        return True



    def __get_metadata__(self):
        '''
        Name: get_metadata
        Parameters: N/A
        Purpose: Populate self.matadata dict with data extracted from r2
                 command: ij
        Return: boolean value indicating success/failure of parsing attributes.
        '''
        try:
            r2obj = self.r2obj.cmdj("ij")
        except IOError as err:
            print("[!] IOError %s ." % str(err))
            if err.errno == errno.EPIPE: # Broken pipe potentially due to perms
                print("[!] Broken pipe, potentially due to permission issues or"
                      "symlink no longer existing")
                return False
        try:
            bin_json = r2obj.get('bin')
            core_json = r2obj.get('core')
        except:
            return False

        dateObj = datetime.now()
        self.metadata['@timestamp'] = dateObj.isoformat()
        self.metadata['file_name'] = core_json.get('file')
        self.metadata['file_format'] = core_json.get('format')

        if self.__check_parsable_file__(self.metadata['file_format'].lower()) == True:
            self.metadata['architecture'] = bin_json.get('arch')
            self.metadata['binary_size'] = core_json.get('humansz')
            self.metadata['language'] = bin_json.get('lang')
            self.metadata['compiler'] = bin_json.get('compiler')
            self.metadata['compiletime'] = bin_json.get('compiled')
            self.metadata['stripped'] = bin_json.get('stripped')
            self.metadata['static'] = bin_json.get('sstatic')
            self.metadata['signed'] = bin_json.get('signed')
            self.metadata['dbg_file'] = bin_json.get('dbg_file')
            self.metadata['endian'] = bin_json.get('endian')
            self.metadata['baseaddr'] = hex(bin_json.get('baddr'))

            # Creating a field to make it easier to search for PDB files in Kibana.
            if len(bin_json.get('dbg_file')) > 0:
                self.metadata['has_debug_string'] = True
            else:
                self.metadata['has_debug_string'] = False
        return True

    def __get_imports_fields__(self):
        '''
        Name: __get_imports_fields__
        Purpose: Create individual fields for each import based on ordinal
        Return: N/A, populate self.metadata dict.
        '''
        try:
            import_json = self.r2obj.cmdj('iaj').get('imports')
            import_list = []
            for i in import_json:
                # Create a field per-ordinal that's created
                self.metadata['import_ordinal_'+str(i.get('ordinal'))] = i.get('name')
                import_list.append(i.get('name')) # crete large list of all imports
            self.metadata["all_imports"] = import_list
        except AttributeError:
            self.metadata["all_imports"] = "Error parsing imports"

    def __get_imports__(self):
        '''
        Name: __get_imports__
        Purpose: Create one field with multiple DLLs
        Return: N/A, populate self.metadata dict.
        '''
        try:
            import_json = self.r2obj.cmdj('iaj').get('imports')
            import_list = []
            for i in import_json:
                import_list.append(i.get('name'))
            self.metadata["all_imports"] = import_list
        except AttributeError:
            self.metadata["all_imports"] = "Error parsing imports"


    def __get_exports_fields__(self):
        '''
        Name: __get_exports_fields__
        Purpose: Create individual fields for each import based on ordinal
        Return: N/A, populate self.metadata dict.
        '''
        try:
            import_json = self.r2obj.cmdj('iaj').get('imports')
            import_list = []
            for i in import_json:
                # Create a field per-ordinal that's created
                self.metadata['import_ordinal_'+str(i.get('ordinal'))] = i.get('name')
                import_list.append(i.get('name')) # crete large list of all imports
            self.metadata["all_imports"] = import_list
        except AttributeError:
            self.metadata["all_imports"] = "Error parsing imports"


    def __get_exports__(self):
        '''
        Name: __get_exports__
        Purpose: Get exports from binaries
        Return: N/A, populate self.metadata dict.
        '''
        try:
            export_json = self.r2obj.cmdj('iaj').get('exports')
            export_list = []
            for i in export_json:
                export_list.append(i.get('name'))
            self.metadata["all_exports"] = export_list
        except AttributeError:
            self.metadata["all_exports"] = "Error parsing exports"

    def run_triage(self):
        '''
        Name: run_triage
        Purpose: Perform metadata triage of binaries.
        Paramters: N/A
        Return: JSON dump of metadata info.
        '''
        self.__get_metadata__()
        self.__get_imports__()
        self.__get_exports__()
        self.__get_hashes__()
        self.__r2_close__() # Close r2 pipe object.
        return json.dumps(self.metadata)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("-d", "--directory", type=str, required=False,
                        help="Directory of files to process.")

    parser.add_argument("-f", "--file", type=str, required=False,
                        help="Single file to process.")

    parser.add_argument("-t", "--rhost", type=str, required=False,
                        help="Remote host to POST to.")

    parser.add_argument("-p", "--rport", type=str, required=False,
                        help="Remote port to POST to.")

    args = parser.parse_args()
    util = Utils()

    if args.directory and args.file:
        print("[!] Error, either specify a directory of binaries or just one "
              "binary.")
        sys.exit(1)

    # Parse and POST a directory of files
    elif (args.directory is not None and args.rhost is not None and args.rport is not None):
        file_list = util.list_files(args.directory)
        for binary in file_list:
            tobj = Triage(binary)
            data = tobj.run_triage()
            util.elk_post(data, args.rhost, args.rport)

    # Parse and POST single file
    elif (args.file is not None and args.rhost is not None and args.rport is not None):
        tobj = Triage(args.file)
        data = tobj.run_triage()
        util.elk_post(data, args.rhost, args.rport)

    # Just parse and print single file
    elif args.file is not None and args.rhost is None and args.rport is None:
        tobj = Triage(args.file)
        print(tobj.run_triage())

    elif args.directory is not None and args.rhost is None and args.rport is None:
        file_list = util.list_files(args.directory)
        for binary in file_list:
            tobj = Triage(binary)
            print(tobj.run_triage())
    else:
        parser.print_help()
