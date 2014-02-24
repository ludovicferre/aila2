using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Symantec.CWoC {
    class aila2 {
        static int Main(string[] args) {
            CLIConfig config = new CLIConfig();
            int result = config.CheckConfig(args);

            if (result == 0 && config.status == CLIConfig.parse_results.check_success) {
                aila2.LogAnalyzer a = new LogAnalyzer(config);
                if (config.stdin) {
                    while (!a.AnalyzeStdin(Console.ReadLine()))
                        ;
                    a.DumpResults();
                    return 0;
                }

                if (!File.Exists(config.file_path)) {
                    Console.WriteLine("The provide file (\"{0}\") is not accessible. The process will terminate now...", config.file_path);
                    return (int)errno.E_INVALID_ARGS;
                }
                a.AnalyzeFile(config.file_path);
                return (int)errno.E_SUCCESS;
            } else if (result == 0 && config.status == CLIConfig.parse_results.check_error) {
                Console.Write(HELP_MESSAGE);
                return (int)errno.E_MISSING_ARGS;
            } else if (result == 0 && config.status == CLIConfig.parse_results.version_request) {
                // Display versions
                Console.WriteLine(VERSION_MESSAGE);
                return (int)errno.E_SUCCESS;
            } else {
                Console.Write(HELP_MESSAGE);
                return (int)errno.E_INVALID_ARGS;
            }
        }

        private enum errno {
            E_SUCCESS = 0,
            E_MISSING_ARGS,
            E_INVALID_ARGS
        }

        private static readonly string VERSION_MESSAGE = "aila2 version 1.\n\nBuilt for .Net 2.0, brought to you by {CWoC}.\n";

        #region static readonly string HELP_MESSAGE
        private static readonly string HELP_MESSAGE = @"
Usage : aila2 [Parameter] [Option(s)]

Parameters:
    -h, --help              Show this help message
    -v, --version           Output program version only

    -f, --file <file_path>  The IIS log file to parse

    --stdin                 The log file data will come from the console input
                            instead of a file.

Options:
    -l, --log-level <lvl>   Output log data <= to <lvl> to stdout:
            --log-level  1 -> error
            --log-level  2 -> warning
            --log-level  4 -> information
            --log-level  8 -> verbose
            --log-level 16 -> debug
    -o, --out-path <path>   The location where the result file will be created.

Samples:
    aila2 -f iis.log
    aila2 --file iis.log -l 4
    aila2 -f iis.log -o c:\inetpub\wwwroot\aila2\

{CWoc} info: http://www.symantec.com/connect/search/apachesolr_search/cwoc
";
        #endregion

        public enum log_levels { error = 1, warning = 2, information = 4, verbose = 8, debugging = 16 };

        class Logger {
            public static void log_evt(log_levels lvl, string s) {
                if ((int)CLIConfig.log_level >= (int)lvl)
                    Console.WriteLine(s);
            }
        }

        class CLIConfig {
            public parse_results status;
            public string file_path;
            public static log_levels log_level = log_levels.error;
            public bool progress_bar;
            public bool stdin;
            public string out_path;

            public CLIConfig() {
                status = parse_results.check_error;

                stdin = false;
                file_path = "";
                progress_bar = true; ;
                out_path = ".";
            }

            public enum parse_results {
                check_success,          // Process
                version_request,        // Display version
                check_error             // Show --help
            };

            public void dump_config() {
                Console.WriteLine("Command line arguments parsing generated the following configuration:");
                Console.WriteLine("File path:\t\t{0}", file_path);
                Console.WriteLine("Output directory:\t{0}", out_path);
                Console.WriteLine("Progress bar:\t\t{0}", progress_bar.ToString());
            }

            public int CheckConfig(string[] argv) {

                int argc = argv.Length;
                int i = 0;

                int valid_args = 0;
                while (i < argc) {
                    Logger.log_evt(log_levels.information, string.Format("#Command line Argument {0}= '{1}'", i, argv[i]));

                    if ((argv[i] == "-h") || argv[i] == "--help") {
                        status = parse_results.check_error;
                        return 0;
                    }
                    if (argv[i] == "--stdin") {
                        stdin = true;
                        valid_args++;
                    }
                    if (argv[i] == "-f" || argv[i] == "--file") {
                        if (argc > i + 1) {
                            file_path = argv[++i];
                            valid_args += 2;
                            Logger.log_evt(log_levels.information, string.Format("File command is called with file path (to be checked) '{0}'", argv[i]));
                            continue;
                        } else {
                            status = parse_results.check_error;
                            return 0;
                        }
                    }
                    if (argv[i] == "-V" || argv[i] == "--version") {
                        status = parse_results.version_request;
                        return 0;
                    }
                    if (argv[i] == "-l" || argv[i] == "--log-level") {
                        try {
                            int l = Convert.ToInt32(argv[i + 1]);
                            log_level = (log_levels)l;
                            valid_args += 2;
                            i++;
                            continue;
                        } catch {
                            status = parse_results.check_error;
                            return -1;
                        }
                    }
                    if (argv[i] == "-o" || argv[i] == "--out-path") {
                        out_path = argv[++i].Replace("\"", "");
                        valid_args += 2;
                    }
                    i++;
                }

                if (argc == valid_args) {
                    status = parse_results.check_success;
                    Logger.log_evt(log_levels.verbose, "Returning success (0) to caller.");
                    if (file_path == "")
                        stdin = true;
                    return 0;
                } else {
                    status = parse_results.check_error;
                    Logger.log_evt(log_levels.warning, "Returning failure (-1) to caller.");
                    return -1;
                }
            }
        }

        class ResultSet {
            public int LineCount;
            public int DataLines;
            public int SchemaDef;

            public int[] MIME_TYPE_hit_counter;

            public int[] IIS_STATUS_hit_counter;
            public int[] IIS_SUB_STATUS_hit_counter;
            public int[] IIS_WIN32_STATUS_hit_counter;

            public long[,] WEBAPP_Hit_counter;
            public long[,] AGENT_Hit_counter;

            public int[,] HOURLY_hit_counter;

            public IpHitLists IP_Handler;

            public ResultSet() {
                LineCount = DataLines = SchemaDef = 0;

                HOURLY_hit_counter = new int[24, 5]; // Total, PostEvent, PkgInfo, GetPolicies, ?

                IIS_STATUS_hit_counter = new int[10];
                IIS_SUB_STATUS_hit_counter = new int[10];
                IIS_WIN32_STATUS_hit_counter = new int[10];

                MIME_TYPE_hit_counter = new int[constants.http_mime_type.Length];

                // We track hit count, total duration and max duration per web-app
                WEBAPP_Hit_counter = new long[constants.atrs_iis_vdir.Length, 3];
                AGENT_Hit_counter = new long[constants.atrs_agent_req.Length, 3];

                IP_Handler = new IpHitLists();
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

        public static readonly string[] SupportedFields = new string[] {
            "date", "time", "cs-method", "cs-uri-stem", "cs-uri-query", "cs-username", "c-ip", "sc-status", "sc-substatus", "sc-win32-status", "time-taken"
        };

        public enum FieldPositions {
            date = 0, time, method, uristem, uriquery, username, ip, status, substatus, win32status, timetaken
        }

        class SchemaParser {
            public string current_schema_string;
            public List<int> field_positions;
            public bool ready;

            public SchemaParser() {
                current_schema_string = "";
                // Assume a max 30 distinct fields are select, safe enough?
                field_positions = new List<int>();
                ready = false;
            }

            public int ParseSchemaString(string schema) {
                schema = schema.Substring(9).TrimEnd(); // Remove the '#Fields: ' head

                if (schema != current_schema_string) {
                    current_schema_string = schema;
                    field_positions.Clear();

                    Logger.log_evt(log_levels.verbose, "Row Schema = " + current_schema_string);

                    string[] fields = schema.Split(' ');
                    int l = 0;
                    foreach (string f in fields) {
                        int i = 0;
                        foreach (string s in SupportedFields) {
                            if (s == f) {
                                field_positions.Add(l);
                                Logger.log_evt(log_levels.debugging, string.Format("We have a match for string {0} at position {1}.", s, l.ToString()));
                                break;
                            }
                            i++;
                        }
                        l++;
                    }
                    int j = 0;
                    foreach (int k in field_positions) {
                        Logger.log_evt(log_levels.debugging, String.Format("{0}-{1}: {2}", j.ToString(), k.ToString(), SupportedFields[j]));
                        j++;
                    }

                    if (field_positions.Count > 0)
                        ready = true;
                    return 1;
                } else {
                    return 0;
                }
            }

        }

        class IpHitLists {
            public SortedDictionary<string, int> ip_list;
            public SortedList<int, List<string>> ip_hitters;

            public IpHitLists() {
                ip_list = new SortedDictionary<string, int>();
                ip_hitters = new SortedList<int, List<string>>();
            }
        }

        class LogAnalyzer {
            private ResultSet results;
            private SchemaParser schema;
            private CLIConfig config;

            private string[] current_line;

            private int _hour;
            private int _timetaken;
            private long _status;
            private long _substatus;
            private long _win32status;
            private string md5_hash;
            private string filename;

            public LogAnalyzer(CLIConfig c) {
                current_line = new string[32];
                config = c;
                md5_hash = "";

                Timer.Init();

                results = new ResultSet();
                schema = new SchemaParser();
            }

            public void AnalyzeFile(string filepath) {

                filename = filepath.Substring(filepath.LastIndexOf('\\') + 1);

                Logger.log_evt(log_levels.information, string.Format("Generating file md5 hash..."));
                try {
                    byte[] hash;
                    using (MD5 md5 = MD5.Create()) {
                        using (FileStream stream = File.OpenRead(filepath)) {
                            hash = md5.ComputeHash(stream);
                        }
                    }

                    StringBuilder sBuilder = new StringBuilder();
                    for (int i = 0; i < hash.Length; i++)
                        sBuilder.Append(hash[i].ToString("x2"));
                    md5_hash = sBuilder.ToString();
                } catch (IOException) {
                    Console.WriteLine("Could not access file {0}. Terminating now...", filename);
                    return;
                } catch (Exception e) {
                    Console.WriteLine(e.Message);
                    Console.WriteLine(e.StackTrace);
                    return;
                }

                string line = "";
                try {
                    using (StreamReader r = new StreamReader(filepath)) {
                        int i = 0;
                        while (r.Peek() >= 0) {
                            line = r.ReadLine();
                            Logger.log_evt(log_levels.debugging, string.Format("Parsing line below ###\n", line));
                            AnalyzeLine(ref line);
                            results.LineCount++;

                            if (++i > 999) {
                                Console.Write("Processed {0} lines...\r", results.LineCount);
                                i = 0;
                            }
                        }
                    }
                } catch (IOException) {
                    Console.WriteLine("Could not access file {0}. Terminating now...", filename);
                    return;
                } catch (Exception e) {
                    Console.WriteLine(e.Message);
                    Console.WriteLine(e.StackTrace);
                    Console.WriteLine(line);

                }
                Timer.Stop();
                DumpResults();
                if (config.progress_bar == true) {
                    Console.WriteLine("We have read {0} lines in {1} milli-seconds.", results.LineCount.ToString(), Timer.duration());
                    Console.WriteLine("The file {0} has {1} schema definition and {2} data lines.", filepath, results.SchemaDef, results.DataLines);
                }
            }

            public bool AnalyzeStdin(string line) {
                if (line == null) {
                    return true;
                }
                Logger.log_evt(log_levels.information, string.Format("Parsing line below :: {0}", line));
                try {
                    AnalyzeLine(ref line);
                } catch (Exception e) {
                    Console.Error.WriteLine("Error! Could not parse the following line:\n{0}.", line);
                    Console.Error.WriteLine(e.Message);
                    return true; // Terminate process on input error
                }
                results.LineCount++;
                return false;
            }

            private void AnalyzeLine(ref string line) {
                line = line.ToLower();
                Logger.log_evt(log_levels.debugging, "Starting detailed line analysis...");
                if (line.StartsWith("#")) {
                    Logger.log_evt(log_levels.debugging, "We have a commented line");
                    if (line.StartsWith("#fields:")) {
                        if (schema.current_schema_string != line) {
                            results.SchemaDef += schema.ParseSchemaString(line);
                        }
                    }
                    return;
                }

                if (!schema.ready || line == "")
                    return;
                Logger.log_evt(log_levels.debugging, "The current line contains data...");

                results.DataLines++;
                // Tokenize the current line
                string[] row_data = line.ToLower().Split(' ');
                int i = 0;
                current_line.Initialize();

                Logger.log_evt(log_levels.debugging, "Loading line data into storage array...");
                foreach (int j in schema.field_positions) {
                    current_line[i] = row_data[j];
                    if (CLIConfig.log_level == log_levels.debugging)
                        Console.WriteLine("{0} ::{1}={2} ", i.ToString(), SupportedFields[i], current_line[i]);
                    i++;
                }

                // Convert the values from string to in now
                _hour = Convert.ToInt32(current_line[(int)FieldPositions.time].Substring(0, 2));
                _timetaken = Convert.ToInt32(current_line[(int)FieldPositions.timetaken]);
                _status = Convert.ToInt64(current_line[(int)FieldPositions.status]);

                if (_status < 300) {
                    // HTTP 20x
                    results.IIS_STATUS_hit_counter[(int) constants.IIS_STATUS_CODES._iis_success]++;
                } else if (_status < 400) {
                    // HTTP 30x
                    results.IIS_STATUS_hit_counter[(int) constants.IIS_STATUS_CODES._iis_redirect]++;
                } else if (_status < 500) {
                    // HTTP 40x
                    results.IIS_STATUS_hit_counter[(int) constants.IIS_STATUS_CODES._iis_client_error]++;
                } else {
                    // HTTP 50x
                    results.IIS_STATUS_hit_counter[(int) constants.IIS_STATUS_CODES._iis_server_error]++;
                }

                _substatus = Convert.ToInt64(current_line[(int)FieldPositions.substatus]);
                _win32status = Convert.ToInt64(current_line[(int)FieldPositions.win32status]);

                Logger.log_evt(log_levels.debugging, "Running analysis - part I (hourly hits) ...");
                // Global hourly stats
                results.HOURLY_hit_counter[_hour, 0]++;

                // Analyse mime types
                Logger.log_evt(log_levels.debugging, "Running analysis - part II (mime type) ...");
                Analyze_MimeTypes(ref current_line[(int)FieldPositions.uristem]);

                // Analyze web-application
                Logger.log_evt(log_levels.debugging, "Running analysis - part III (web-apps) ...");
                Analyze_WebApp(ref current_line[(int)FieldPositions.uristem]);

                string c_ip = current_line[(int)FieldPositions.ip];
                if (results.IP_Handler.ip_list .ContainsKey(c_ip)) {
                    results.IP_Handler.ip_list[c_ip]++;
                } else {
                    results.IP_Handler.ip_list.Add(c_ip, 1);
                }
            }

            private int Analyze_MimeTypes(ref string uri) {
                int i = 0;
                foreach (string type in constants.http_mime_type) {
                    Logger.log_evt(log_levels.debugging, string.Format("Checking mime-types {0}", type));
                    if (uri.EndsWith(type)) {
                        // Increment mime-type counter
                        results.MIME_TYPE_hit_counter[i]++;
                        Logger.log_evt(log_levels.debugging, string.Format("Current request mime type is {0}.", type));
                        return i;
                    }
                    i++;
                }
                results.MIME_TYPE_hit_counter[i - 1]++;
                return i - 1;
            }

            private int Analyze_WebApp(ref string uri) {
                int i = 0;
                foreach (string app in constants.atrs_iis_vdir) {
                    Logger.log_evt(log_levels.debugging, string.Format("Checking web-app {1}: {0}", app, i.ToString()));
                    if (uri.StartsWith(app)) {
                        Logger.log_evt(log_levels.debugging, string.Format("Current request web-app is {0}.", app));
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
                results.WEBAPP_Hit_counter[i, 1] += Convert.ToInt64(current_line[(int)FieldPositions.timetaken]);
                if (results.WEBAPP_Hit_counter[i, 2] < Convert.ToInt64(current_line[(int)FieldPositions.timetaken]))
                    results.WEBAPP_Hit_counter[i, 2] = Convert.ToInt64(current_line[(int)FieldPositions.timetaken]);
                return 0;
            }

            private int Analyze_NSAgent(ref string uri) {
                int i = 0;
                for (i = 0; i < constants.atrs_agent_req.Length; i++) {
                    string page_name = constants.atrs_agent_req[i];
                    if (uri.EndsWith(page_name)) {
                        results.AGENT_Hit_counter[i, 0]++;
                        results.AGENT_Hit_counter[i, 1] += Convert.ToInt64(current_line[(int)FieldPositions.timetaken]);
                        if (results.AGENT_Hit_counter[i, 2] < Convert.ToInt64(current_line[(int)FieldPositions.timetaken]))
                            results.AGENT_Hit_counter[i, 2] = Convert.ToInt64(current_line[(int)FieldPositions.timetaken]);
                        break;
                    }
                }
                if (i == (int)constants.ATRS_AGENT_REQ._post_event_asp || i == (int)constants.ATRS_AGENT_REQ._post_event_aspx) {
                    // Add to hourly accounting
                    results.HOURLY_hit_counter[_hour, 1]++;
                } else if (i == (int)constants.ATRS_AGENT_REQ._get_pkg_info) {
                    results.HOURLY_hit_counter[_hour, 2]++;
                } else if (i == (int)constants.ATRS_AGENT_REQ._get_client_policy) {
                    results.HOURLY_hit_counter[_hour, 3]++;
                }
                return 0;
            }

            private void SaveToFile(string filepath, string data) {
                using (StreamWriter outfile = new StreamWriter(filepath.ToLower())) {
                    outfile.Write(data);
                }
            }

            private string FloatToDottedString(float f) {
                string s = f.ToString();
                return s.Replace(',', '.');
            }

            public void DumpResults() {

                StringBuilder output = new StringBuilder();
                output.AppendFormat("{{\n\t\"file\" : \"{0}\",\n", filename);
                output.AppendFormat("\t\"hash\" : \"{0}\",\n", md5_hash);
                output.AppendFormat("\t\"linecount\" : {0},\n", results.DataLines.ToString());
                output.Append("\t\"stats\" : {\n");

                // HOURLY STATS
                output.Append("\t\t\"hourly\" : [\n");
                output.Append("\t\t\t[\"Hour\", \"Total hit #\", \"Post Event\", \"Get Client Policy\", \"Get Package Info\"],\n");
                for (int j = 0; j < 24; j++) {
                    output.AppendFormat("\t\t\t[\"{0}\", {1}, {2}, {3}, {4}],\n", j.ToString(), results.HOURLY_hit_counter[j, 0].ToString(), results.HOURLY_hit_counter[j, 1].ToString(), results.HOURLY_hit_counter[j, 2].ToString(), results.HOURLY_hit_counter[j, 3].ToString());
                }
                output.Length = output.Length - 2; // Remove the last ",\n"
                output.AppendLine("\n\t\t],");


                // MIME TYPE STATS
                output.AppendFormat("\t\t\"mime_type\" : [\n");
                output.AppendFormat("\t\t\t[\"Mime type\", \"Hit #\"],\n");
                for (int j = 0; j < results.MIME_TYPE_hit_counter.Length; j++) {
                    output.AppendFormat("\t\t\t[\"{0}\", {1}],\n", constants.http_mime_type[j], results.MIME_TYPE_hit_counter[j].ToString());
                }
                output.Length = output.Length - 2; // Remove the last ",\n"
                output.AppendLine("\n\t\t],");

                // WEB-APPLICATION STATS
                output.AppendFormat("\t\t\"web_application\" : [\n");
                output.AppendFormat("\t\t\t[\"Web-application\", \"Hit #\", \"Sum(time-taken)\", \"Max(time-taken)\", \"Avg(time-taken)\"],\n");
                for (int j = 0; j < constants.atrs_iis_vdir.Length; j++) {
                    float avg = 0;
                    if (results.WEBAPP_Hit_counter[j, 1] > 0) {
                        avg = (float)results.WEBAPP_Hit_counter[j, 1] / (float)results.WEBAPP_Hit_counter[j, 0];
                    }
                    output.AppendFormat("\t\t\t[\"{0}\", {1}, {2}, {3}, {4}],\n", constants.atrs_iis_vdir[j], results.WEBAPP_Hit_counter[j, 0].ToString(), results.WEBAPP_Hit_counter[j, 1].ToString(), results.WEBAPP_Hit_counter[j, 2].ToString(), FloatToDottedString(avg));
                }
                output.Length = output.Length - 2; // Remove the last ",\n"
                output.AppendLine("\n\t\t],");

                // HTTP Status code stats
                output.AppendFormat("\t\t\"http_status\" : [\n");
                output.AppendFormat("\t\t\t[\"Http-status\", \"Hit #\"],\n");
                for (int j = 0; j < 4; j++) {
                    output.AppendFormat("\t\t\t[\"{0}\", {1}],\n", constants.iis_status_code[j], results.IIS_STATUS_hit_counter[j].ToString());
                }
                output.Length = output.Length - 2; // Remove the last ",\n"
                output.AppendLine("\n\t\t],");


                // AGENT INTERFACE STATS
                output.AppendFormat("\t\t\"agent_interface\" : [\n");
                output.AppendFormat("\t\t\t[\"Agent interface\", \"Hit #\", \"Sum(time-taken)\", \"Max(time-taken)\", \"Avg(time-taken)\"],\n");
                for (int j = 0; j < constants.atrs_agent_req.Length; j++) {
                    float avg = 0;
                    if (results.AGENT_Hit_counter[j, 1] > 0) {
                        // Console.WriteLine("Calculation = {0} / {1}...", results.WEBAPP_Hit_counter[j, 2], results.WEBAPP_Hit_counter[j, 1]);
                        avg = (float)results.AGENT_Hit_counter[j, 1] / (float)results.AGENT_Hit_counter[j, 0];
                    }
                    output.AppendFormat("\t\t\t[\"{0}\", {1}, {2}, {3}, {4}],\n", constants.atrs_agent_req[j], results.AGENT_Hit_counter[j, 0].ToString(), results.AGENT_Hit_counter[j, 1].ToString(), results.AGENT_Hit_counter[j, 2].ToString(), FloatToDottedString(avg));
                }

                output.Length = output.Length - 2; // Remove the last ",\n"
                output.Append("\n\t\t],");

                // IP ADDRESS TOP 20 HITTERS
                foreach (KeyValuePair<string, int> kvp in results.IP_Handler.ip_list) {
                    // Console.WriteLine("{0}:\t\t{1}", kvp.Key, kvp.Value.ToString());
                    if (results.IP_Handler.ip_hitters.ContainsKey(kvp.Value)) {
                        // Update existing value (i.e. add ip to list)
                        results.IP_Handler.ip_hitters[kvp.Value].Add(kvp.Key);
                    } else {
                        List<string> l = new List<string>();
                        l.Add(kvp.Key);
                        results.IP_Handler.ip_hitters.Add(kvp.Value, l);
                    }
                }

                int i = results.IP_Handler.ip_hitters.Count;
                output.AppendFormat("\n\t\t\"ip_hit_top\" : [\n");
                output.AppendFormat("\t\t\t[\"Hit count\", \"IP Address\"],\n");

                for (int j = 1; j < 21; j++) {

                    if (i - j <= 0) {
                        break;
                    }
                    int hit_count = results.IP_Handler.ip_hitters.Keys[i - j];
                    List<string> ip_list = results.IP_Handler.ip_hitters.Values[i - j];

                    if (ip_list.Count < 2) {
                        output.AppendFormat("\t\t\t[\"{0}\",", ip_list[0]);
                        output.AppendFormat("{0}],\n", hit_count.ToString());
                    } else {
                        foreach (string s in ip_list) {
                            output.AppendFormat("\t\t\t[\"{0}\", {1}],\n", s, hit_count.ToString());
                        }
                        output.Length = output.Length - 2;
                    }

                }

                // CLOSE THE JSON
                output.AppendLine("\n\t\t]\n\t}\n}");

                if (!config.out_path.EndsWith("\\")) {
                    config.out_path = config.out_path + "\\";
                }

                if (config.stdin) {
                    Console.WriteLine(output.ToString());
                } else {
                    SaveToFile(config.out_path + filename.Replace(".log", ".json"), output.ToString());
                }
            }
        }

    }
}
