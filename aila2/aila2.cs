using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Symantec.CWoC {
    class aila2 {
        private static readonly int version = 1;
        static int Main(string[] args) {
            if (args.Length == 0) {
                Console.Write(HELP_MESSAGE);
                return -1;
            } else {
                CLIConfig config = new CLIConfig();
                int result = config.CheckConfig(args);

                if (result == 0 && config.status == CLIConfig.parse_results.check_success) {
                    LogAnalyzer a = new LogAnalyzer(config);
                    a.AnalyzeFile(config.file_path);
                    return result;
                } else if (result == 0 && config.status == CLIConfig.parse_results.check_error) {
                    Console.Write(HELP_MESSAGE);
                    return result;
                } else if (result == 0 && config.status == CLIConfig.parse_results.version_request) {
                    // Display versions
                    Console.WriteLine(VERSION_MESSAGE);
                    return result;
                } else {
                    Console.Write(HELP_MESSAGE);
                    return result; // Error
                }
            }
        }

        private static readonly string VERSION_MESSAGE = "aila2 (Altiris IIS Log Analyser) is at version " + version + "\n\nBuilt for .Net 2.0, brought to you by {CWoC}.\n";

        private static readonly string HELP_MESSAGE = "\nUsage : aila2 [Parameter] [Option(s)]\n\nParameters:\n\t  -h, --help to show this help message\n\t  -f, --file <path_to_file>\n\nOptions:\n\t  -c, --csv-format\tFormat output using tab seperated values\n\t  -l, --log-level <lvl>\tOutput log data <= to <lvl> to stderr:\n\t\t--log-level  1 -> error\n\t\t--log-level  2 -> warning\n\t\t--log-level  4 -> information\n\t\t--log-level  8 -> verbose\n\t\t--log-level 16 -> debug\n\t -n0, --no-zero\t\tShow results including 0 counts\n\t-ndc, --no-dump-cache\tDo no writes the string cache content to file\n\t -nt, --no-topper\tDo not output the top 20 entries from caches\n\t -js, --json\t\tProduces JSON formatted output for aila-web\n\t  -S, --summary\t\tParse file for summary review only\n\t  -V, --version\t\tOutput program version only\n\nSamples:\n\taila2 --file iis.log --no-zero --log-level 8\n\taila2 -f iis.log -l 4 -n0\n\taila2 -f iis.log -n0\n\n{CWoc} info: http://www.symantec.com/connect/search/apachesolr_search/cwoc\n";

    }

    class Logger {
        public enum log_levels { error = 1, warning = 2, information = 4, verbose = 8, debugging = 16 };
        public static void log_evt(log_levels lvl, string s) {
            if ((int)CLIConfig.log_level >= (int) lvl)
                Console.WriteLine(s);
        }
    }
    
    class CLIConfig {
        public parse_results status;
        public string file_path;
        public bool no_null;
        public bool summary_only;
        public static Logger.log_levels log_level = Logger.log_levels.warning;
        public bool dump_csv;
        public bool csv_format;
        public bool query_shell;
        public bool no_topper;
        public bool json_output;
        public bool debug;
        public bool progress_bar;
        public string out_path;
        public int time_taken;

        public CLIConfig() {
            status = parse_results.check_error;
            file_path = "";
            no_null = false;
            summary_only = true;
            dump_csv = true;
            csv_format = false;
            query_shell = false;
            no_topper = false;
            json_output = false;
            debug = false;
            progress_bar = true;
            out_path = "";
            time_taken = 0;
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
                Logger.log_evt(Logger.log_levels.information, string.Format("#Command line Argument {0}= '{1}'", i, argv[i]));

                if ((argv[i] == "-h") || argv[i] == "--help") {
                    status = parse_results.check_error;
                    return 0;
                }

                if (argv[i] == "-f" || argv[i] == "--file") {
                    if (argc > i + 1) {
                        file_path = argv[++i];
                        current_check = true;
                        Logger.log_evt(Logger.log_levels.information , string.Format("File command is called with file path (to be checked) '{0}'", argv[i]));
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

                if (argv[i] == "-np" || argv[i] == "--no-progress")
                    progress_bar = false;

                if (argv[i] == "-l" || argv[i] == "--log-level") {
                    try {
                        int l = Convert.ToInt32(argv[i + 1]);
                        log_level = (Logger.log_levels) l;
                        i++;
                    } catch {
                        status = parse_results.check_error;
                    }
                }

                if (argv[i] == "-t" || argv[i] == "--time-taken") {
                    dump_csv = true;
                    time_taken = Convert.ToInt32(argv[++i]);
                }

                if (argv[i] == "-o" || argv[i] == "--out-path") {
                    out_path = argv[++i];
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
                status = parse_results.check_success;
                if (csv_format == true)
                    progress_bar = false;
                Logger.log_evt(Logger.log_levels.verbose, "Returning success (0) to caller.");
                return 0;
            } else {
                status = parse_results.check_error;
                Logger.log_evt(Logger.log_levels.warning, "Returning failure (-1) to caller.");
                return -1;
            }
        }
    }

    class ResultSet {
        public int LineCount;
        public int DataLines;
        public int SchemaDef;

        public int[] MIME_TYPE_hit_counter;

        public int [] IIS_STATUS_hit_counter;
        public int [] IIS_SUB_STATUS_hit_counter;
        public int [] IIS_WIN32_STATUS_hit_counter;

        public long [,] WEBAPP_Hit_counter;
        public long [,] AGENT_Hit_counter;

        public int [,] HOURLY_hit_counter;

        public ResultSet() {
            LineCount = DataLines = SchemaDef = 0;

            HOURLY_hit_counter = new int[24, 5]; // Total, PostEvent, PkgInfo, GetPolicies, ?

            IIS_STATUS_hit_counter = new int[10];
            IIS_SUB_STATUS_hit_counter = new int[10];
            IIS_WIN32_STATUS_hit_counter = new int[10];

            MIME_TYPE_hit_counter = new int[constants.http_mime_type.Length];

            // We track hit count, total duration and max duration per web-app
            WEBAPP_Hit_counter = new long[constants.atrs_iis_vdir.Length, 3];
            AGENT_Hit_counter = new  long[constants.atrs_agent_req.Length, 3];

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

    class SchemaParser {
        public string current_schema_string;
        public List<int> field_positions;

        public SchemaParser() {
            current_schema_string = "";
            // Assume a mx 30 distinct fields are select, safe?
            field_positions = new List<int>();
        }

        public static readonly string[] SupportedFields = new string[] {
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

        public enum FieldPositions {
            date = 0, time, method, uristem, uriquery, username, ip, status, substatus, win32status, timetaken
        }

        public int ParseSchemaString(string schema) {
            schema = schema.Substring(9).TrimEnd();

            if (schema != current_schema_string) {
                current_schema_string = schema;

                Logger.log_evt(Logger.log_levels.verbose, "Row Schema = " + current_schema_string);

                string[] fields = schema.Split(' ');
                int l = 0;
                foreach (string f in fields) {
                    int i = 0;
                    foreach (string s in SupportedFields) {
                        if (s == f) {
                            field_positions.Add(l);
                            Logger.log_evt(Logger.log_levels.debugging, string.Format("We have a match for string {0} at position {1}.", s, l.ToString()));
                            break;
                        }
                        i++;
                    }
                    l++;
                }
                int j = 0;
                foreach (int k in field_positions) {
                    Logger.log_evt(Logger.log_levels.debugging, String.Format("{0}-{1}: {2}", j.ToString(), k.ToString(), SupportedFields[j]));
                    j++;
                }
                return 1;
            } else {
                return 0;
            }
        }

    }

    class LogAnalyzer {
        private ResultSet results;
        private SchemaParser schema;
        private CLIConfig config;

        private string [] current_line;

        private int _hour;
        private int _timetaken;
        private int _status;
        private int _substatus;
        private long _win32status;

        private string md5_hash;
        private string filename;

        private StreamWriter dump_writer;


        public LogAnalyzer (CLIConfig c) {
            current_line = new string [11];
            config = c;
            md5_hash = "";
        }


        public void AnalyzeFile (string filepath) {
            Timer.Init();

            results = new ResultSet();
            schema = new SchemaParser();

            filename = filepath.Substring(filepath.LastIndexOf('\\') + 1);

            Logger.log_evt(Logger.log_levels.information, string.Format("Generating file md5 hash..."));
            byte [] hash;
            using (MD5 md5 = MD5.Create()) {
                using (FileStream stream = File.OpenRead(filepath)) {
                    hash = md5.ComputeHash(stream);
                }
            }

            StringBuilder sBuilder = new StringBuilder();
            for (int i = 0; i < hash.Length; i++)
                sBuilder.Append(hash[i].ToString("x2"));
            md5_hash = sBuilder.ToString();

            if (config.csv_format) {
                foreach (string s in SchemaParser.SupportedFields)
                    Console.Write("{0};", s);
            }
            if (config.dump_csv) {
                dump_writer = new StreamWriter(config.out_path + "\\" + filename.Replace(".log", "_" + config.time_taken.ToString() + ".log"));
                dump_writer.Write("#Fields: ");
                foreach (string s in SchemaParser.SupportedFields)
                    dump_writer.Write("{0} ", s);
                dump_writer.Write("\n");
            }

            string line = "";
            try {
                using (StreamReader r = new StreamReader(filepath)){
                    int i = 0;
                    while (r.Peek() >= 0) {
                        line = r.ReadLine();
                        Logger.log_evt(Logger.log_levels.debugging, string.Format("Parsing line below ###\n", line));
                        AnalyzeLine(ref line);
                        results.LineCount++;

                        if (++i > 9999 && config.progress_bar) {
                            Console.Write("Processed {0} lines...\r", results.LineCount);
                            i = 0;
                        }
                    }
                }
            } catch (Exception e){
                Console.WriteLine(e.Message);
                Console.WriteLine(e.StackTrace);
                Console.WriteLine(line);
            }
            // Close the dump writer now...
            dump_writer.Flush();
            dump_writer.Close();
            dump_writer.Dispose();

            if (!config.csv_format) {
                DumpResults();
                if (config.progress_bar == true) {
                    Console.WriteLine("We have read {0} lines in {1} milli-seconds.", results.LineCount.ToString(), Timer.duration());
                    Console.WriteLine("The file {0} has {1} schema definition and {2} data lines.", filepath, results.SchemaDef, results.DataLines);
                }
            }
        }

        private void AnalyzeLine(ref string line) {
            Logger.log_evt(Logger.log_levels.debugging, "Starting detailed line analysis...");
            if (line.StartsWith("#")) {
                Logger.log_evt(Logger.log_levels.debugging, "We have a commented line");
                if (line.StartsWith("#Fields:")) {
                    if (schema.current_schema_string != line) {
                        results.SchemaDef += schema.ParseSchemaString(line.ToLower());
                    }
                }
            } else {
                Logger.log_evt(Logger.log_levels.debugging, "The current line contains data...");

                results.DataLines++;
                // Tokenize the current line
                string[] row_data = line.ToLower().Split(' ');
                int i = 0;
                current_line.Initialize();

                Logger.log_evt(Logger.log_levels.debugging, "Loading line data into storage array...");
                foreach (int j in schema.field_positions) {
                    current_line[i] = row_data[j];
                    if(CLIConfig.log_level == Logger.log_levels.debugging)
                        Console.WriteLine("{0} ::{1}={2} ", i.ToString(), SchemaParser.SupportedFields[i], current_line[i]);
                    i++;
                }

                if (config.csv_format) {
                    Console.WriteLine(line.Replace(' ', ';'));
                } else {

                    // Convert the values from string to in now
                    _hour = Convert.ToInt32(current_line[(int)SchemaParser.FieldPositions.time].Substring(0, 2));
                    _timetaken = Convert.ToInt32(current_line[(int)SchemaParser.FieldPositions.timetaken]);
                    _status = Convert.ToInt32(current_line[(int)SchemaParser.FieldPositions.status]);;
                    _substatus = Convert.ToInt32(current_line[(int)SchemaParser.FieldPositions.substatus]);;
                    _win32status = Convert.ToInt64(current_line[(int)SchemaParser.FieldPositions.win32status]); ;

                    if (config.dump_csv && _timetaken > config.time_taken) {
                        foreach (string s in current_line)
                            dump_writer.Write("{0} ", s);
                        dump_writer.Write("\n");
                    }

                    Logger.log_evt(Logger.log_levels.debugging, "Running analysis - part I (hourly hits) ...");
                    // Global hourly stats
                    results.HOURLY_hit_counter[_hour, 0]++;

                    // Analyse mime types
                    Logger.log_evt(Logger.log_levels.debugging, "Running analysis - part II (mime type) ...");
                    Analyze_MimeTypes(ref current_line[(int)SchemaParser.FieldPositions.uristem]);
                    
                    // Analyze web-application
                    Logger.log_evt(Logger.log_levels.debugging, "Running analysis - part III (web-apps) ...");
                    Analyze_WebApp(ref current_line[(int)SchemaParser.FieldPositions.uristem]);
                }
            }
        }

        private int Analyze_MimeTypes(ref string uri) {
            int i = 0;
            foreach (string type in constants.http_mime_type) {
                Logger.log_evt(Logger.log_levels.debugging, string.Format("Checking mime-types {0}", type));
                if (uri.EndsWith(type)) {
                    // Increment mime-type counter
                    results.MIME_TYPE_hit_counter[i]++;
                    Logger.log_evt(Logger.log_levels.debugging, string.Format("Current request mime type is {0}.", type));
                    return i;
                }
                i++;
            }
            results.MIME_TYPE_hit_counter[i-1]++;
            return i -1;
        }

        private int Analyze_WebApp(ref string uri) {
            int i = 0;
            foreach (string app in constants.atrs_iis_vdir) {
                Logger.log_evt(Logger.log_levels.debugging, string.Format("Checking web-app {1}: {0}", app, i.ToString()));
                if (uri.StartsWith(app)) {
                    Logger.log_evt(Logger.log_levels.debugging, string.Format("Current request web-app is {0}.", app));
                    break;
                }
                i++;
            }

            if (i == 0) {
                // We are inside the Altiris-NS-Agent web-app. Do further analysis.
                Analyze_NSAgent(ref uri);
            } else if (i >= constants.atrs_iis_vdir.Length) {
                i = constants.atrs_iis_vdir.Length - 1;
            }
            results.WEBAPP_Hit_counter[i, 0]++;
            results.WEBAPP_Hit_counter[i, 1] += Convert.ToInt64(current_line[(int)SchemaParser.FieldPositions.timetaken]);
            if (results.WEBAPP_Hit_counter[i, 2] < Convert.ToInt64(current_line[(int)SchemaParser.FieldPositions.timetaken]))
                results.WEBAPP_Hit_counter[i, 2] = Convert.ToInt64(current_line[(int)SchemaParser.FieldPositions.timetaken]);
            return 0;
        }

        private int Analyze_NSAgent(ref string uri) {
            int i = 0;
            for (i = 0; i < constants.atrs_agent_req.Length; i++) {
                string page_name = constants.atrs_agent_req[i];
                if (uri.EndsWith(page_name)) {
                    results.AGENT_Hit_counter[i, 0]++;
                    results.AGENT_Hit_counter[i, 1] += Convert.ToInt64(current_line[(int)SchemaParser.FieldPositions.timetaken]);
                    if (results.AGENT_Hit_counter[i, 2] < Convert.ToInt64(current_line[(int)SchemaParser.FieldPositions.timetaken]))
                        results.AGENT_Hit_counter[i, 2] = Convert.ToInt64(current_line[(int)SchemaParser.FieldPositions.timetaken]);
                    break;
                }
            }
            if (i == (int)constants.ATRS_AGENT_REQ._post_event_asp || i == (int) constants.ATRS_AGENT_REQ._post_event_aspx) {
                // Add to hourly accounting
                results.HOURLY_hit_counter[_hour, 1]++;
            } else if (i == (int) constants.ATRS_AGENT_REQ._get_pkg_info) {
                results.HOURLY_hit_counter[_hour, 2]++;
            } else if (i == (int) constants.ATRS_AGENT_REQ._get_client_policy){
                results.HOURLY_hit_counter[_hour, 3]++;
            }
            return 0;
        }

        private void SaveToFile(string filepath, string data) {
            using (StreamWriter outfile = new StreamWriter(filepath.ToLower())) {
                outfile.Write(data);
            }
        }

        public void DumpResults() {

            StringBuilder output = new StringBuilder();
            output.AppendFormat("\n{{\n\t\"file\" : \"{0}\",\n", filename);
            output.AppendFormat("\t\"hash\" : \"{0}\",\n", md5_hash);
            output.AppendFormat("\t\"linecount\" : {0},\n", results.DataLines.ToString());
            output.Append("\t\"stats\" : {\n");

            // HOURLY STATS

            output.Append("\t\t\"hourly\" : [\n");
            output.Append("\t\t\t[\"Hour\", \"Total hit #\", \"Post Event\", \"Get Client Policy\", \"Get Package Info\"],\n");
            for (int j = 0; j < 24; j++) {
                if (j == 23)
                    output.AppendFormat("\t\t\t[\"{0}\", {1}, {2}, {3}, {4}]\n\t\t], \n", j.ToString(), results.HOURLY_hit_counter[j, 0].ToString(), results.HOURLY_hit_counter[j, 1].ToString(), results.HOURLY_hit_counter[j, 2].ToString(), results.HOURLY_hit_counter[j, 3].ToString());
                else
                    output.AppendFormat("\t\t\t[\"{0}\", {1}, {2}, {3}, {4}], \n", j.ToString(), results.HOURLY_hit_counter[j, 0].ToString(), results.HOURLY_hit_counter[j, 1].ToString(), results.HOURLY_hit_counter[j, 2].ToString(), results.HOURLY_hit_counter[j, 3].ToString());
            }

            // MIME TYPE STATS

            output.AppendFormat("\t\t\"mime_type\" : [\n");
            output.AppendFormat("\t\t\t[\"Mime type\", \"Hit #\"],\n");
            for (int j = 0; j < results.MIME_TYPE_hit_counter.Length; j++) {
                if (j == results.MIME_TYPE_hit_counter.Length - 1)
                    output.AppendFormat("\t\t\t[\"{0}\", {1}]\n\t\t], \n", constants.http_mime_type[j], results.MIME_TYPE_hit_counter[j].ToString());
                else
                    output.AppendFormat("\t\t\t[\"{0}\", {1}], \n", constants.http_mime_type[j], results.MIME_TYPE_hit_counter[j].ToString());
            }

            // WEB-APPLICATION STATS

            output.AppendFormat("\t\t\"web_application\" : [\n");
            output.AppendFormat("\t\t\t[\"Web-application\", \"Hit #\", \"Sum(time-taken)\", \"Max(time-taken)\"], \n");
            for (int j = 0; j < constants.atrs_iis_vdir.Length; j++) {
                if (j == results.WEBAPP_Hit_counter.Length / 3 - 1) {
                    output.AppendFormat("\t\t\t[\"{0}\", {1}, {2}, {3}] \n", constants.atrs_iis_vdir[j], results.WEBAPP_Hit_counter[j, 0].ToString(), results.WEBAPP_Hit_counter[j, 1].ToString(), results.WEBAPP_Hit_counter[j, 2].ToString());
                } else {
                    output.AppendFormat("\t\t\t[\"{0}\", {1}, {2}, {3}], \n", constants.atrs_iis_vdir[j], results.WEBAPP_Hit_counter[j, 0].ToString(), results.WEBAPP_Hit_counter[j, 1].ToString(), results.WEBAPP_Hit_counter[j, 2].ToString());
                }
            }

            output.AppendFormat("\t\t],\n");

            // AGENT INTERFACE STATS

            output.AppendFormat("\t\t\"agent_interface\" : [\n");
            output.AppendFormat("\t\t\t[\"Agent interface\", \"Hit #\", \"Sum(time-taken)\", \"Max(time-taken)\"], \n");
            for (int j = 0; j < constants.atrs_agent_req.Length; j++) {
                if (j == results.AGENT_Hit_counter.Length / 3 - 1) {
                    output.AppendFormat("\t\t\t[\"{0}\", {1}, {2}, {3}]\n", constants.atrs_agent_req[j], results.AGENT_Hit_counter[j, 0].ToString(), results.AGENT_Hit_counter[j, 1].ToString(), results.AGENT_Hit_counter[j, 2].ToString());
                } else {
                    output.AppendFormat("\t\t\t[\"{0}\", {1}, {2}, {3}],\n", constants.atrs_agent_req[j], results.AGENT_Hit_counter[j, 0].ToString(), results.AGENT_Hit_counter[j, 1].ToString(), results.AGENT_Hit_counter[j, 2].ToString());
                }
            }

            output.Append("\t\t]\n\t}\n}\n");
            Console.WriteLine(output.ToString());
            SaveToFile(config.out_path + "\\" + filename + ".json", output.ToString());

        }

    }
}
