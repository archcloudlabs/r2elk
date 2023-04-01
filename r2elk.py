#!/usr/bin/env python3
"""
    R2ELK is a Python binary parsing utility that leverages the Radare2 Python
    API. Metadata extracted from the binaries is then presented to the end user
    in JSON format.
"""
try:
    from os import access
    from os import R_OK
    from datetime import datetime
    from stat import S_ISREG
    import sys
    import os
    import errno
    import json
    import argparse
    import r2pipe
    import requests
    import yara
    import pefile
except ImportError as import_err:
    print("[!] Missing package %s." % str(import_err))
    sys.exit(1)


class Utils:
    """
    Helper utilities to aid in loading binaries for triage.
    """

    def list_files(self, directory):
        """
        Name: list_files
        Purpose: List all files within a directory and run R2 triage methods.
                 This method will not follow symlinks.
                 https://docs.python.org/3.7/library/stat.html
        Parameters: [directory] string path to directory of binaries.
        Return: List of files within a directory.
        """
        normal_files = []
        for filename in os.listdir(directory):
            file_path = os.path.join(directory, filename)
            try:
                file_info = os.lstat(file_path)
            except NotADirectoryError as non_dir:
                print("[!] Error, %s" % non_dir)
                sys.exit(1)
            except EnvironmentError:
                continue
            else:
                # Check for non-symlink files and readable files.
                if S_ISREG(file_info.st_mode) and access(file_path, R_OK):
                    normal_files.append(file_path)
                else:
                    print("[*] Skipping processing of %s" % str(file_path))
        return normal_files

    def __check__url__(self, url):
        """
        Name: __check_url__
        Parameters: [url] string value
        Purpose: Verify that HTTP or HTTPS is within the CLI remote URL.
        """
        if url[0:4] != ("http" or "https"):
            return False
        return True

    def elk_post(self, post_data, rhost, rport, index):
        """
        Name: elk_post
        Purpose: Post JSON data to Elastic endpoint (could also be logstash)
        Parameters: [rhost] remote Elasticserver to post to.
            [rport] remote port that Elastic is running on.
        Return: boolean based on success or failure of HTTP POST.
        """
        if not self.__check__url__(rhost):
            rhost = "http://" + rhost
            print("[!] Failed to specify http or https."
                  " Defaulting to %s:%s/%s/_doc" % (rhost, rport, index))

        headers = {"Content-Type": "application/json"}
        try:
            req = requests.post(rhost + ":" + rport + "/" + index + "/_doc",
                                headers=headers, data=post_data)
            if req.status_code == 201:
                print("[+] File %s completed." %
                      json.loads(post_data).get('file_name'))
            return True
        except requests.exceptions.RequestException as err:
            print("[!] Error posting data!\n\\t %s" % str(err))
            return False

    def write_output(self, fname, json_blob):
        """
        Write json output to disk for filebeats or other log shipper
        fname: file name to write to
        json_blob: JSON to write data to.
        """

        try:
            if "/" in fname:
                fname = fname.split("/")[-1]
            with open(fname+".json", "w") as fout:
                fout.write(json.dumps(json_blob))
        except IOError as io_err:
            print("io_err")


class Triage:
    """
    Perform binary metadata analysis via R2 and cleanup output for ES ingestion.
    """

    def __init__(self, fname, yara_rule_file=None):
        self.metadata = {}  # Dict populated by private functions.
        self.current_binary = fname
        self.r2obj = self.__r2_load__()

        if yara_rule_file is not None:
            self.yara_rules = yara_rule_file

    def __r2_load__(self):
        """
        Name: __r2_load__
        Purpose: Create a r2 instance for triage object to use.
        Return: r2pipe object.
        """
        try:
            return r2pipe.open(self.current_binary)
        except IOError:
            print("[!] Error opening file %s." % str(self.current_binary))
            sys.exit(1)

    def __r2_close__(self):
        """
        Name: close radare2 handle
        Parameters: N/A
        Return: N/A
        """
        self.r2obj.quit()

    def get_hashes(self):
        """
        Name: __get__hashes__
        Purpose: Leverage r2pipe to get MD5 and SHA1 hash
        Return: N/A, populate self.metadata dict.
        """
        hashes = self.r2obj.cmdj('itj')

        try:
            self.metadata["imphash"] = pefile.PE(self.current_binary)
        except:
            self.metadata["imphash"] = "Error getting IMPHash for file"

        try:
            self.metadata["md5"] = hashes.get("md5")
            self.metadata["sha1"] = hashes.get("sha1")
            self.metadata["sha256"] = hashes.get("sha256")
        except:
            self.metadata["md5"] = "Error getting MD5 for file"
            self.metadata["sha1"] = "Error getting SHA1 for file"
            self.metadata["sha256"] = "Error getting SHA256 for file"

    def __check_parsable_file__(self, ftype):
        """
        Name: __check_parsable_file__
        Purpose: Check that a valid binary file is trying to be parsed.
        Return: Boolean indicating whether or not its a valid file type.
        """
        valid_types = ["pe", "elf", "elf64", "pe64", "pe64+", "pe32+", "pe+"]
        if ftype not in valid_types:
            return False
        return True

    def get_sections(self):
        """
        Name: __get__hashes__
        Purpose: Leverage r2pipe to get MD5 and SHA1 hash
        Return: N/A, populate self.metadata dict.
        """
        sections = self.r2obj.cmdj('iSj')
        try:
            self.metadata["sections"] = sections
        except:
            self.metadata["sections"] = "Error getting executable section information"

    def get_metadata(self):
        """
        Name: get_metadata.

        Parameters: N/A
        Purpose: Populate self.matadata dict with data extracted from r2.
                 command: ij

        Return: Boolean value indicating success/failure of parsing attributes.
        """
        try:
            r2obj = self.r2obj.cmdj("ij")
        except IOError as err:
            print("[!] IOError %s ." % str(err))
            if err.errno == errno.EPIPE:  # Broken pipe potentially due to perms
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

        if self.__check_parsable_file__(self.metadata['file_format'].lower()):
            self.metadata['architecture'] = bin_json.get('arch')
            self.metadata['binary_size'] = core_json.get('humansz')
            self.metadata['language'] = bin_json.get('lang')
            self.metadata['compiler'] = bin_json.get('compiler')
            self.metadata['compiletime'] = bin_json.get('compiled')
            self.metadata['stripped'] = bin_json.get('stripped')
            self.metadata['static'] = bin_json.get('static')
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

    def get_imports_fields(self):
        """
        Name: __get_imports_fields__
        Purpose: Create individual fields for each import based on ordinal
        Return: N/A, populate self.metadata dict.
        """
        try:
            import_json = self.r2obj.cmdj('iaj').get('imports')
            import_list = []
            for i in import_json:
                # Create a field per-ordinal that's created
                self.metadata['import_ordinal_' + str(i.get('ordinal'))] = i.get('name')
                import_list.append(i.get('name'))  # crete large list of all imports
            self.metadata["all_imports"] = import_list
        except AttributeError:
            self.metadata["all_imports"] = "Error parsing imports"

    def get_imports(self):
        """
        Name: __get_imports__
        Purpose: Create one field with multiple DLLs
        Return: N/A, populate self.metadata dict.
        """
        try:
            import_json = self.r2obj.cmdj('iaj').get('imports')
            import_list = []
            for i in import_json:
                import_list.append(i.get('name'))
            self.metadata["all_imports"] = import_list
            self.metadata["num_of_imports"] = len(import_list)
        except AttributeError:
            self.metadata["all_imports"] = "Error parsing imports"

    def get_exports_fields(self):
        """
        Name: __get_exports_fields__
        Purpose: Create individual fields for each import based on ordinal
        Return: N/A, populate self.metadata dict.
        """
        try:
            import_json = self.r2obj.cmdj('iaj').get('imports')
            import_list = []
            for i in import_json:
                # Create a field per-ordinal that's created
                self.metadata['import_ordinal_' + str(i.get('ordinal'))] = i.get('name')
                import_list.append(i.get('name'))  # crete large list of all imports
            self.metadata["all_imports"] = import_list
        except AttributeError:
            self.metadata["all_imports"] = "Error parsing imports"

    def get_exports(self):
        """
        Name: __get_exports__
        Purpose: Get exports from binaries
        Return: N/A, populate self.metadata dict.
        """
        try:
            export_json = self.r2obj.cmdj('iaj').get('exports')
            export_list = []
            for i in export_json:
                export_list.append(i.get('name'))
            self.metadata["all_exports"] = export_list
            self.metadata["num_of_exports"] = len(export_list)
        except AttributeError:
            self.metadata["all_exports"] = "Error parsing exports"

    def get_strings_fields(self):
        """
        Name: get_strings_fields
        Purpose: Extract strings from binaries and create individual fields.
        Return: N/A, populate self.metadata dict.
        """
        try:
            string_json = self.r2obj.cmdj('izj')
            for count, string in enumerate(string_json):
                self.metadata['string_' + str(count)] = string.get('string')
        except AttributeError:
            self.metadata["binary_strings"] = "Error parsing strings"

    def get_strings(self, max_length=100):
        """
        Name: get_strings
        Param: max_length, integer to specify how many values to pull vs all of the strings from within a binary.
        Purpose: Extract strings from binaries.
        Return: N/A, populate self.metadata dict.
        """
        try:
            string_json = self.r2obj.cmdj('izj')
            string_fields = []
            try:
                for string in string_json[0:max_length]:
                    string_fields.append(string.get('string'))
                self.metadata["strings"] = string_fields
            except IndexError:
                self.metadata["strings"] = "Error parsing strings"
        except AttributeError:
            self.metadata["strings"] = "Error parsing strings"

    def yara_scan(self, fname):
        """
        Name:yara_scan
        Purpose: run Yara rules against a binary and return matching rule set.
        Parameters: [fname] binary file to read in
        Return: N/A, populates self.metadata dict.
        """
        try:
            yaraObj = yara.compile(self.yara_rules)
        except AttributeError as err:
            print("[!] Attribute error: %s" % str(err))
            sys.exit(1)
        except yara.Error as err:
            print("[!] Error: %s" % str(err))
            sys.exit(1)

        matches = yaraObj.match(fname)
        yara_matches = []
        for match in matches:
            yara_matches.append(match.rule)

        self.metadata["yara_rules"] = yara_matches

    def run_triage(self, yarascan=None):
        """
        Name: run_triage
        Purpose: Perform metadata triage of binaries.
        Paramters: N/A
        Return: JSON dump of metadata info.
        """
        self.get_metadata()
        self.get_imports()
        self.get_exports()
        self.get_hashes()
        self.get_strings()
        self.get_sections()
        if yarascan is not None:
            self.yara_scan(self.current_binary)

        self.__r2_close__()  # Close r2 pipe object.
        return json.dumps(self.metadata)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("-d", "--directory", type=str, required=False,
                        help="Directory of files to process.")

    parser.add_argument("-f", "--file", type=str, default=None, required=False,
                        help="Single file to process.")

    parser.add_argument("-t", "--rhost", type=str, required=False,
                        help="Remote host to POST to.")

    parser.add_argument("-p", "--rport", type=str, required=False,
                        help="Remote port to POST to.")

    parser.add_argument("-i", "--index", type=str, default="samples",
                        required=False, help="Elasticsearch Index")

    parser.add_argument("-y", "--yara", type=str, default=None, required=False, help="Yara files to process")
    parser.add_argument("-v", "--verbose", action="store_true", default=None, required=False, help="Write data out")

    args = parser.parse_args()
    util = Utils()

    if args.directory and args.file:
        print("[!] Error, either specify a directory of binaries or just one "
              "binary.")
        sys.exit(1)

    # Parse and POST a directory of files
    elif args.directory is not None and args.rhost is not None and args.rport is not None:
        file_list = util.list_files(args.directory)
        for binary in file_list:
            tobj = Triage(binary, args.yara)
            data = tobj.run_triage(args.yara)
            util.elk_post(data, args.rhost, args.rport, args.index)

    # Parse and POST single file
    elif args.file is not None and args.rhost is not None and args.rport is not None:
        tobj = Triage(args.file, args.yara)
        data = tobj.run_triage(args.yara)
        util.elk_post(data, args.rhost, args.rport, args.index)

    # Just parse and print single file
    elif args.file is not None and args.rhost is None and args.rport is None:
        tobj = Triage(args.file, args.yara)
        json_data = tobj.run_triage(args.yara)
        if args.verbose:
            print(json_data)
        util.write_output(args.file, json_data)

    # Just parse and print a directory of files
    elif args.directory is not None and args.rhost is None and args.rport is None:
        file_list = util.list_files(args.directory)
        for binary in file_list:
            tobj = Triage(binary, args.yara)
            json_data = tobj.run_triage(args.yara)
            if args.verbose:
                print(json_data)
    else:
        parser.print_help()
