using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace Symantec.CWoC {
    class aila2_runner {
        static void Main(string[] args) {
            // Start with static source and destination dirs
            string source = @"C:\inetpub\logs\logfiles\w3svc1\";
            string destination = @"d:\aila2";

            /* Process outline
             *      Get the list of log files in source
             *      Get the list of json files in destination
             *      Remove the extensions of logs and json files
             *      Match the file lists. Any log file without a json file should be processed
             */

            // Starting with the source dir and files handling
            string[] in_files = Directory.GetFiles(source, "*.log");

            if (in_files.Length == 0) {
                // Nothing to do - return now!
                return;
            }

            string[] in_names = new string[in_files.Length];
            for (int i = 0; i < in_files.Length; i++) {
                string f = in_files[i];
                in_names[i] = f.Substring(f.LastIndexOf("\\") + 1);
            }

            // Then get the json files
            string[] out_files = Directory.GetFiles(destination, "*.json");

            if (out_files.Length == 0) {
                goto skip;
            }

            string[] out_names = new string[out_files.Length];

            for (int i = 0; i < out_files.Length; i++) {
                string f = out_files[i];
                out_names[i] = f.Substring(f.LastIndexOf("\\") + 1);
                Console.WriteLine("{0} :: {1} :: {2}", i.ToString(), f, out_names[i]);
            }

            // Clear out log files here
            for (int i = 0; i < in_names.Length; i++) {
                // If the entry was cleared out continue
                if (in_names[i] == "") {
                    continue;
                }
                // Else check if the equivalant out string exists
                foreach (string f in out_names) {
                    string in_short = in_names[i].Substring(0, in_names[i].Length - 4);
                    string out_short = f.TrimEnd().Substring(0, f.Length - 5);
//                    Console.WriteLine("{0} :: {1}", in_short, out_short);
                    if (in_short == out_short) {
                        in_names[i] = "";
                        break;
                    }
                }
            }

        skip:
            // Now we can process each non-empty entry in in_names
            foreach (string f in in_names) {
                if (f == "") {
                    continue;
                }
                Console.WriteLine("-f \"{0}{1}\" -o \"{2}\"", source, f, destination);

                Process aila2 = new Process();
                aila2.StartInfo.FileName = "aila2\\aila2.exe";
//                aila2.StartInfo.FileName = "cmd /k"; 
                aila2.StartInfo.Arguments = String.Format("-f \"{0}{1}\" -o \"{2}\"", source, f, destination);
                aila2.StartInfo.UseShellExecute = false;
                aila2.StartInfo.RedirectStandardOutput = true;
                aila2.Start();

                Console.WriteLine(aila2.StandardOutput.ReadToEnd());

                aila2.WaitForExit();
            }
        }
    }
}
