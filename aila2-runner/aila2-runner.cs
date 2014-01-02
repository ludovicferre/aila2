using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace Symantec.CWoC {
    class aila2_runner {
        static int Main(string[] args) {
            // Start with static source and destination dirs

            string source = "";
            string destination = "";

            // Handle the command line arguments here
            if (args.Length == 0) {
                Console.WriteLine(help_message);
                return -1;
            } else if (args.Length == 1) {
                if (args[0].ToLower() == "-v") {
                    Console.WriteLine("aila2-runner version 1");
                    return 0;
                }
                Console.WriteLine(help_message);
                if (args[0].ToLower() == "/?" || args[0].ToLower() == "--help") {
                    return 0;
                }
                return -1;
            } else {
                for (int i = 0; i < args.Length; i++) {
                    if (args[i].ToLower() == "-i" || args[i].ToLower() == "--in-path") {
                        source = args[++i];
                        continue;
                    }
                    if (args[i].ToLower() == "-o" || args[i].ToLower() == "--out-path") {
                        destination = args[++i];
                        continue;
                    }
                }
            }

            // All is okay, we can proceed now

            // First we normalise the paths to ensure they are back slash terminated
            if (!source.EndsWith("\\")) {
                source = source + "\\";
            }
            if (!destination.EndsWith("\\")) {
                destination= destination + "\\";
            }

            // Get left data now
            string[] in_files = Directory.GetFiles(source, "*.log");

            if (in_files.Length == 0) // Nothing to do - return now!
                return 0;

            string[] in_names = new string[in_files.Length];
            get_filenames(ref in_files, ref in_names);

            string[] out_files = Directory.GetFiles(destination, "*.json");

            if (out_files.Length == 0) {
                goto skip_outdir_empty;
            }

            // Get right data now
            string[] out_names = new string[out_files.Length];
            get_filenames(ref out_files, ref out_names);

            // Remove log files that were already parsed
            get_todolist(ref in_names, ref out_names);

        skip_outdir_empty:
            // Now we can process each non-empty entry in in_names
            // but we skip the last file (as it should be today's files)
            for (int i = 0; i < in_names.Length - 1; i++) {
                string f = in_names[i];
                if (f == "") {
                    continue;
                }
                Console.WriteLine("Now running aila2.exe -f \"{0}{1}\" -o \"{2}\"...", source, f, destination);

                Process aila2 = new Process();

                aila2.StartInfo.FileName = "aila2.exe";
                aila2.StartInfo.Arguments = String.Format("-f \"{0}{1}\" -o \"{2}\"", source, f, destination);
                aila2.StartInfo.UseShellExecute = false;
                aila2.StartInfo.RedirectStandardOutput = true;
                aila2.Start();

                Console.WriteLine(aila2.StandardOutput.ReadToEnd());

                aila2.WaitForExit();
            }
            return 0;
        }

        public static void get_filenames(ref string[] list, ref string[] names) {
            for (int i = 0; i < list.Length; i++) {
                names[i] = list[i].Substring(list[i].LastIndexOf("\\") + 1);
            }
        }

        public static void get_todolist(ref string[] left, ref string[] right) {
            for (int i = 0; i < left.Length; i++) {
                // If the entry was cleared out continue
                if (left[i] == "") {
                    continue;
                }
                // Else check if the equivalant out string exists
                for (int j = 0; j < right.Length; j++ ) {
                    string left_file = left[i].Substring(0, left[i].Length - 4);
                    string right_file = right[j].Substring(0, right[j].Length - 5);
                    if (left_file == right_file) {
                        left[i] = "";
                        break;
                    }
                }
            }
        }

        public static string help_message = @"
Usage: aila2-runner -i <input path> -o <output path>

aila2-runner will parse the input path for IIS log files (*.log) and will check
if a corresponding file exists in the output path (*.json). If not the log file
will be parsed with aila2 to generate a json result file in the output path.

Parameters:

    -h, --help          Show this help message
    -v, --version       Output program version only

    -i, --in-path       The path to the directory containing the IIS log files
    -o, --out-path      The path to the directory where the result files are
                        stored.

";
    }
}
