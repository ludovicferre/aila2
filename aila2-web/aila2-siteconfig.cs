using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace  Symantec.CWoC {
    class aila2_web {
        static int Main(string[] args) {
            // Parse the current directory or directory provided via -d and generate a json file listing all json files.
            // The file will be named siteconfig.json and excluded from the search ;).

            string[] argv = args;
            int argc = argv.Length;

            string dir_path = string.Empty;

            string help_message = @"
Usage: aila2-siteconfig -i <json directory path>

Output a json formated string to the console defining a sitename string, a
schema_version int and a file_list string array (listing all json files found
in the provided path), as shown in this sample:

    {
            ""sitename"" : ""aila2-web2"",
            ""schema_version"" : 1,
            ""max_graphs"" : 60,
            ""file_list"" : [
                    ""u_ex140101.json"",
                    ""u_ex131231.json"",
                    ""u_ex131230.json""
            ]
    }

Additional command line options:

    -v, --version   Display the tool version
    /?, --help      Display the tool usage (this message).
";
            string version_message = "aila2-siteconfig version 1";

            if (argc == 1) {
                // Check if the caller is requesting version, if not print help
                if (argv[0] == "-v" || argv[0] == "--version") {
                    Console.WriteLine(version_message);
                    return 0;
                } else {
                    Console.WriteLine(help_message);
                    if (argv[0] == "/?" || argv[0] == "--help") {
                        return 0; // Help requested - return success.
                    } else {
                        return -1; // Incorrect agrs provided. Return error.
                    }
                }
            } else if (argc > 2 || argc == 0) {
                Console.WriteLine(help_message);
                return -1;
            }

            for (int i = 0; i < argc; i++) {
                if (argv[i] == "-i" && argc > 1)
                    dir_path = argv[++i];
            }

            if (dir_path.Length == 0 || dir_path == string.Empty)
                dir_path = Directory.GetCurrentDirectory();

            if (!Directory.Exists(dir_path)) {
                Console.WriteLine("The provide input path ({0}) is not valid. Returning now...", dir_path);
                return -1;
            }

            string filename = "";

            StringBuilder json_data = new StringBuilder();
            json_data.AppendLine("{\n\t\"sitename\" : \"aila2-web\",\n\t\"schema_version\" : 1,\n\t\"max_graphs\": 60,\n\t\"file_list\" : [");

            string [] files = Directory.GetFiles(dir_path, "*.json");
            Array.Sort(files);

            for (int i = 0; i < files.Length; i++) {
                if (files[i].EndsWith("siteconfig.json")) {
                    continue;
                }
                filename = files[i].Substring(files[i].LastIndexOf("\\") + 1);
                json_data.AppendFormat("\t\t\"{0}\",\n", filename);
            }

            json_data.Length = json_data.Length - 2; // Remove the last comma + \n
            json_data.AppendLine("\n\t]\n}");

            Console.WriteLine(json_data.ToString());
            return 0;
        }
    }
}
