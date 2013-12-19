using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace Symantec.CWoC {
    class aila2 {
        static void Main(string[] args) {
            if (args.Length == 0) {
                // Display help message
            } else {
                CLIConfig config = new CLIConfig();
                int result = config.CheckConfig(args);

                if (result == 0 && config.status == CLIConfig.parse_results.check_success) {
                    LogAnalyzer a = new LogAnalyzer();
                    a.AnalyzeFile(config.file_path);
                }
            }
        }
    }

    class Logger {
        public static void log_evt(string s) {
            Console.WriteLine(s);
        }
    }
    
    class CLIConfig {
        public parse_results status;
        public string file_path;
        public bool no_null;
        public bool summary_only;
        public int log_level;
        public bool dump_cache;
        public bool csv_format;
        public bool query_shell;
        public bool no_topper;
        public bool json_output;
        public bool debug;
        public bool progress_bar;

        public CLIConfig() {
            status = parse_results.check_error;
            file_path = "";
            no_null = false;
            summary_only = true;
            log_level = 2;
            dump_cache = true;
            csv_format = false;
            query_shell = false;
            no_topper = false;
            json_output = false;
            debug = false;
            progress_bar = true;
        }

        public enum parse_results {
            check_success,          // Process
            version_request,        // Display version
            check_error             // Show --help
        };

        public int CheckConfig(string[] argv) {

            int argc = argv.Length;
            int i = 0;
            bool current_check = false;

            while (i < argc) {
                Logger.log_evt(string.Format("#Command line Argument %d= '%s'", i, argv[i]));

                if ((argv[i] == "-h") || argv[i] == "--help") {
                    status = parse_results.check_error;
                    return 0;
                }

                if (argv[i] == "-f" || argv[i] == "--file") {
                    if (argc > i + 1) {
                        file_path = argv[++i];
                        current_check = true;
                        Logger.log_evt(String.Format("File command is called with file path (to be checked) '{0}'", argv[i]));
                    } else {
                        current_check = false;
                    }
                }

                if (argv[i] == "-V" || argv[i] == "--version") {
                    status = parse_results.version_request;
                    return 0;
                }

                if (argv[i] == "-c" || argv[i] == "--csv-format") {
                    csv_format = true;
                    no_topper = true;
                }

                if (argv[i] == "-n0" || argv[i] == "--no-zero")
                    no_null = true;

                if (argv[i] == "-S" || argv[i] == "--summary")
                    summary_only = true;

                if (argv[i] == "-npc" || argv[i] == "--no-progress")
                    progress_bar = false;

                if (argv[i] == "-l" || argv[i] == "--log-level") {
                    try {
                        int l = Convert.ToInt32(argv[i + 1]);
                        log_level = l;
                        i++;
                    } catch {
                        status = parse_results.check_error;
                    }
                }

                if (argv[i] == "-ndc" || argv[i] == "--no-dump-cache") {
                    dump_cache = false;
                }

                if (argv[i] == "-qs" || argv[i] == "--query-shell") {
                    query_shell = true;
                    csv_format = false;
                    dump_cache = false;
                }

                if (argv[i] == "-nt" || argv[i] == "--no-topper") {
                    no_topper = true;
                }
                if (argv[i] == "-js" || argv[i] == "--json") {
                    json_output = true;
                    csv_format = false;
                }
                i++;
            }
            if (current_check == true) {
                // dump_option_set(opt);
                status = parse_results.check_success;
                if (csv_format == true)
                    progress_bar = false;
                Logger.log_evt("Returning success (0) to caller.");
                return 0;
            } else {
                status = parse_results.check_error;
                Logger.log_evt("Returning failure (-1) to caller.");
                return -1;
            }
        }
    }

    class ResultSet {
        public int LineCount;
        public int DataLines;
        public int SchemaDef;

        public ResultSet() {
            LineCount = 0;
            DataLines = 0;
            SchemaDef = 0;
        }
    }

    class SchemaParser {
        public string current_schema_string;
        private List<int> field_positions;

        public SchemaParser() {
            current_schema_string = "";
            // Assume a mx 30 distinct fields are select, safe?
            field_positions = new List<int>();
        }

        private readonly string[] SupportedFields = new string[] {
            "date",
            "time",
            "cs-method",
            "cs-uri-stem",
            "cs-uri-query",
            "cs-username",
            "c-ip",
            "sc-status",
            "sc-substatus",
            "sc-win32-status",
            "time-taken"
        };

        public int ParseSchemaString (string schema) {
            schema = schema.Substring(9).TrimEnd();

            // Check whether the schema is changed or already supported
            if (schema != current_schema_string) {
                // New schema - save it now
                current_schema_string = schema;

                // Tokenise the string
                string[] fields = schema.Split(' ');
                Console.WriteLine("Schema field count = {0}.", fields.Length.ToString());
                foreach (string f in SupportedFields) {
                    int i = 0;
                    foreach (string s in fields) {
                        if (s == f) {
                            field_positions.Add(i);
                            Console.WriteLine("We have a match for string {0} at position {1}.", s, i.ToString());
                            break;
                        }
                        i++;
                    }
                }
                int j = 0;
                foreach (int k in field_positions) {
                    Console.WriteLine("{0}-{1}: {2}", j.ToString(), k.ToString(), SupportedFields[j]);
                    j++;
                }
                return 1;
            } else {
                return 0;
            }
        }

    }

    class Timer {
        private static Stopwatch chrono;

        public static void Init() {
            chrono = new Stopwatch();
            chrono.Start();
        }

        public static void Start() {
            chrono.Start();
        }
        public static void Stop() {
            chrono.Stop();
        }
        public static string tickCount() {
            return chrono.ElapsedTicks.ToString();
        }
        public static string duration() {
            return chrono.ElapsedMilliseconds.ToString();
        }
    }


    class LogAnalyzer {
        private ResultSet results;
        private SchemaParser schema;

        public void AnalyzeFile (string filename) {
            // Count lines
            results = new ResultSet();
            schema = new SchemaParser();
            Timer.Init();
            try {
                using (StreamReader r = new StreamReader(filename)){
                    int i = 0;
                    while (r.Peek() >= 0) {
                        string line = r.ReadLine();
                        AnalyzeLine(line);
                        results.LineCount++;

                        if (++i > 9999) {
                            Console.Write("Processed {0} lines...\r", results.LineCount);
                            i = 0;
                        }
                    }
                }
            } catch (Exception e){
                Console.WriteLine(e.Message);
            }
            Console.WriteLine("We have read {0} lines in {1} milli-seconds.", results.LineCount.ToString(), Timer.duration());
            Console.WriteLine("The file {0} has {1} schema definition and {2} data lines.", filename, results.SchemaDef, results.DataLines);
        }

        private void AnalyzeLine(string line) {
            if (line.StartsWith("#")) {
                if (line.StartsWith("#Fields:")) {
                    if (schema.current_schema_string != line) {
                        results.SchemaDef += schema.ParseSchemaString(line.ToLower());
                    }
                    // Console.WriteLine(line);
                }
            } else {
                results.DataLines++;
            }
        }
    }
}
