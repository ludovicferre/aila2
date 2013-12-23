using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace  Symantec.CWoC {
    class aila2_web {
        static void Main(string[] args) {
            // Parse the current directory or directory provided via -d and generate a json file listing all json files.
            // The file will be named siteconfig.json and excluded from the search ;).

            string[] argv = args;
            int argc = argv.Length;

            string dir_path = string.Empty;

            for (int i = 0; i < argc; i++) {
                if (argv[i] == "-i" && argc > 1)
                    dir_path = argv[++i];
            }

            if (dir_path.Length == 0 || dir_path == string.Empty)
                dir_path = Directory.GetCurrentDirectory();

            string filename = "";
            Console.WriteLine("{\n\t\"sitename\" : \"aila2-web\",\n\t\"schema_version\" : 1,\n\t\"file_list\" : [");
            //foreach (string f in Directory.GetFiles(dir_path)) {
            string [] files = Directory.GetFiles(dir_path);
            int n = 1;
            foreach (string f in files) {
                if (f.ToLower().EndsWith("siteconfig.json")) {
                    n++;
                }
            }
            for (int i = 0; i < files.Length; i++) {
                string f = files[i];
                filename = f.Substring(f.LastIndexOf("\\") + 1);
                if (filename.EndsWith(".json") && filename != "siteconfig.json") {
                    if (i == files.Length - n) {
                        Console.WriteLine("\t\t\"{0}\"", filename);
                    } else {
                        Console.WriteLine("\t\t\"{0}\",", filename);
                    }
                }
            }
            Console.WriteLine("\t]\n}");
        }
    }
}
