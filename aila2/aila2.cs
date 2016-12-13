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

        private static readonly string VERSION_MESSAGE = "aila2 version 3.\n\nBuilt for .Net 2.0, brought to you by {CWoC}.\n";

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
            public long[,] TASK_Hit_counter;
            public long[,] IRM_Hit_counter;
			
			public long RX_BYTES; //Client to server bytes count (receive by server -> RX_BYTES)
			public long TX_BYTES; // Server to client bytes count (sent by server -> TX_BYTES)
			

            public long[,] HOURLY_hit_counter;
            public long[,] HOURLY_rxtx_counter;

            public IpHitLists IP_Handler;

            public ResultSet() {
                LineCount = DataLines = SchemaDef = 0;

                HOURLY_hit_counter = new long[24, 10]; // Total, PostEvent, PkgInfo, GetPolicies, TaskManagement, InventoryRuleManagement
                HOURLY_rxtx_counter = new long[24, 10]; // RX Bytes, TX Bytes
				
				RX_BYTES = 0;
				TX_BYTES = 0;

                IIS_STATUS_hit_counter = new int[10];
                IIS_SUB_STATUS_hit_counter = new int[10];
                IIS_WIN32_STATUS_hit_counter = new int[10];

                MIME_TYPE_hit_counter = new int[constants.http_mime_type.Length];

                // We track hit count, total duration and max duration per web-app and high hit interfaces
                WEBAPP_Hit_counter = new long[constants.atrs_iis_vdir.Length, 3];
                AGENT_Hit_counter = new long[constants.atrs_agent_req.Length, 3];
                TASK_Hit_counter = new long[constants.atrs_task_req.Length, 3];
                IRM_Hit_counter = new long[constants.atrs_irm_params.Length, 3];

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
            "date", "time", "cs-method", "cs-uri-stem", "cs-uri-query", "cs-username", "c-ip", "sc-status", "sc-substatus", "sc-win32-status", "cs-bytes", "sc-bytes", "time-taken"
        };

        class SchemaParser {
            public string current_schema_string;
			public Dictionary<string, int> fields;
            public bool ready;

            public SchemaParser() {
                current_schema_string = "";
				fields = new Dictionary<string, int>();
                ready = false;
            }

            public int ParseSchemaString(string schema) {
                schema = schema.Substring(9).TrimEnd(); // Remove the '#Fields: ' head

                if (schema != current_schema_string) {
                    current_schema_string = schema;
                    fields.Clear();

                    Logger.log_evt(log_levels.verbose, "Row Schema = " + current_schema_string);

                    string[] _fields = schema.Split(' ');
                    int l = 0;
                    foreach (string f in _fields) {
                        int i = 0;
                        foreach (string s in SupportedFields) {
                            if (s == f) {
								fields.Add(s, l);
                                Logger.log_evt(log_levels.debugging, string.Format("We have a match for string {0} at position {1}.", s, l.ToString()));
                                break;
                            }
                            i++;
                        }
                        l++;
                    }
					foreach (KeyValuePair<string, int> kvp in fields) {
						Logger.log_evt(log_levels.debugging, string.Format("{0} : {1}", kvp.Key, kvp.Value.ToString()));
					}
                    if (fields.Count > 0)
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

            public string GetIpList() {
                // Generate the ordered (des) hit list
                StringBuilder output = new StringBuilder();
                output.Append("IP address, Hit #\n");
                for (int i = ip_hitters.Count - 1; i > 0; i--) {
                    foreach (string c_ip in ip_hitters.Values[i]) {
                        output.AppendFormat("{0}, {1}\n", c_ip, ip_hitters.Keys[i].ToString());
                    }
                }
                return output.ToString();
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
			private long _txbytes;
			private long _rxbytes;

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
                            AnalyzeLine(line);
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
                    AnalyzeLine(line);
                } catch (Exception e) {
                    Console.Error.WriteLine("Error! Could not parse the following line:\n{0}.", line);
                    Console.Error.WriteLine(e.Message);
                    return true; // Terminate process on input error
                }
                results.LineCount++;
                return false;
            }

            private void AnalyzeLine(string line) {
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

				current_line = line.ToLower().Split(' ');

                // Convert the values from string to in now				
				if (schema.fields.ContainsKey("time")) {
					_hour = Convert.ToInt32(current_line[schema.fields["time"]].Substring(0, 2));
				} else {
					_hour = 0;
				}
				if (schema.fields.ContainsKey("time-taken")) {
					_timetaken = Convert.ToInt32(current_line[(int) schema.fields["time-taken"]]);
				} else {
					_timetaken = 0;
				}
				if (schema.fields.ContainsKey("sc-status")) {
					_status = Convert.ToInt64(current_line[schema.fields["sc-status"]]);
				} else {
					_status = 0;
				}
				
				if (schema.fields.ContainsKey("cs-bytes")) {
					_rxbytes = Convert.ToInt64(current_line[schema.fields["cs-bytes"]]);
				} else {
					_rxbytes = 0;
				}
				if (schema.fields.ContainsKey("sc-bytes")) {
					_txbytes = Convert.ToInt64(current_line[schema.fields["sc-bytes"]]);
				} else {
					_txbytes = 0;
				}

				results.RX_BYTES += _rxbytes;
				results.TX_BYTES += _txbytes;
				
				results.HOURLY_rxtx_counter[_hour, 0] += _rxbytes;
				results.HOURLY_rxtx_counter[_hour, 1] += _txbytes;

				
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

				if (schema.fields.ContainsKey("sc-substatus")) {
					_substatus = Convert.ToInt64(current_line[schema.fields["sc-substatus"]]);
				} else {
					Logger.log_evt(log_levels.debugging, "Field sc-substatus is missing!!!");
					_substatus = 0;
				}
				
				if (schema.fields.ContainsKey("sc-win32-status")) {
					_win32status = Convert.ToInt64(current_line[schema.fields["sc-win32-status"]]);
				} else {
					Logger.log_evt(log_levels.debugging, "Field sc-win32-status is missing!!!");
					_win32status = 0;
				}

                Logger.log_evt(log_levels.debugging, "Running analysis - part I (hourly hits) ...");

                // Global hourly stats
                results.HOURLY_hit_counter[_hour, 0]++;

                // Analyse mime types
                Logger.log_evt(log_levels.debugging, "Running analysis - part II (mime type) ...");
				if (schema.fields.ContainsKey("cs-uri-stem")) {
					Analyze_MimeTypes(current_line[schema.fields["cs-uri-stem"]]);
				} else {
					Logger.log_evt(log_levels.debugging, "Field cs-uri-stem is missing!!!");
				}

                // Analyze web-application
                Logger.log_evt(log_levels.debugging, "Running analysis - part III (web-apps) ...");
                if (schema.fields.ContainsKey("cs-uri-stem") && schema.fields.ContainsKey("cs-uri-query")) {
					Analyze_WebApp(current_line[schema.fields["cs-uri-stem"]], current_line[schema.fields["cs-uri-query"]]);
				}

				if (schema.fields.ContainsKey("c-ip")) {
					string c_ip = current_line[schema.fields["c-ip"]];
					if (results.IP_Handler.ip_list.ContainsKey(c_ip)) {
						results.IP_Handler.ip_list[c_ip]++;
					} else {
						results.IP_Handler.ip_list.Add(c_ip, 1);
					}
				}
            }

            private int Analyze_MimeTypes(string uri) {
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

            private int Analyze_WebApp(string uri, string param) {
                int i = 0;
                foreach (string app in constants.atrs_iis_vdir) {
                    Logger.log_evt(log_levels.debugging, string.Format("Checking web-app {1}: {0}", app, i.ToString()));
                    if (uri.StartsWith(app)) {
                        Logger.log_evt(log_levels.debugging, string.Format("Current request web-app is {0}.", app));
                        break;
                    }
                    i++;
                }

                if (i == (int) constants.ATRS_IIS_VDIR._atrs_ns_agent) {
                    // We are inside the Altiris-NS-Agent web-app. Do further analysis.
                    Analyze_NSAgent(uri);
                } else if (i == (int) constants.ATRS_IIS_VDIR._atrs_tm || i == (int) constants.ATRS_IIS_VDIR._atrs_cts) {
                    Analyze_TaskMgmt(uri);
                } else if (i == (int) constants.ATRS_IIS_VDIR._atrs_irm) {
                    Analyze_IRM(param);
                } else if (i >= constants.atrs_iis_vdir.Length) {
                    i = constants.atrs_iis_vdir.Length - 1;
                }
                results.WEBAPP_Hit_counter[i, 0]++;
				
				if (schema.fields.ContainsKey("time-taken")) {
					results.WEBAPP_Hit_counter[i, 1] += Convert.ToInt64(current_line[schema.fields["time-taken"]]);
					if (results.WEBAPP_Hit_counter[i, 2] < Convert.ToInt64(current_line[schema.fields["time-taken"]])) {
						results.WEBAPP_Hit_counter[i, 2] = Convert.ToInt64(current_line[schema.fields["time-taken"]]);
					}
				}
                return 0;
            }

            private int Analyze_NSAgent(string uri) {
                int i = 0;
                for (i = 0; i < constants.atrs_agent_req.Length; i++) {
                    string page_name = constants.atrs_agent_req[i];
                    if (uri.EndsWith(page_name)) {
                        results.AGENT_Hit_counter[i, 0]++;
						if (schema.fields.ContainsKey("time-taken")) {
							results.AGENT_Hit_counter[i, 1] += Convert.ToInt64(current_line[schema.fields["time-taken"]]);
							if (results.AGENT_Hit_counter[i, 2] < Convert.ToInt64(current_line[schema.fields["time-taken"]]))
								results.AGENT_Hit_counter[i, 2] = Convert.ToInt64(current_line[schema.fields["time-taken"]]);
						}
                        break;
                    }
                }
                if (i == (int)constants.ATRS_AGENT_REQ._post_event_asp || i == (int)constants.ATRS_AGENT_REQ._post_event_aspx) {
                    // Add to hourly accounting
                    results.HOURLY_hit_counter[_hour, (int) constants.HOURLY_TABLE._postevent]++;
                } else if (i == (int)constants.ATRS_AGENT_REQ._get_pkg_info) {
                    results.HOURLY_hit_counter[_hour, (int) constants.HOURLY_TABLE._packageinfo]++;
                } else if (i == (int)constants.ATRS_AGENT_REQ._get_client_policy) {
                    results.HOURLY_hit_counter[_hour, (int) constants.HOURLY_TABLE._getpolicies]++;
                } else if (i == (int)constants.ATRS_AGENT_REQ._connection_test) {
                    results.HOURLY_hit_counter[_hour, (int) constants.HOURLY_TABLE._connection_test]++;
                }
                return 0;
            }

            private void Analyze_TaskMgmt(string uri) {
                int i = 0;
                for (i = 0; i < constants.atrs_task_req.Length; i++) {
                    string page_name = constants.atrs_task_req[i];
                    if (uri.EndsWith(page_name)) {
                        results.TASK_Hit_counter[i, 0]++;
                        results.TASK_Hit_counter[i, 1] += Convert.ToInt64(current_line[schema.fields["time-taken"]]);
                        if (results.TASK_Hit_counter[i, 2] < Convert.ToInt64(current_line[schema.fields["time-taken"]]))
                            results.TASK_Hit_counter[i, 2] = Convert.ToInt64(current_line[schema.fields["time-taken"]]);
                        break;
					}
                }
                // Add to hourly accounting
                results.HOURLY_hit_counter[_hour, (int) constants.HOURLY_TABLE._taskmgmt]++;
            }

            private void Analyze_IRM(string param) {
                int i = 0;
                for (i = 0; i < constants.atrs_irm_params.Length; i++) {
                    string query_name = constants.atrs_irm_params[i];
                    if (param.StartsWith(query_name)) {
                        results.IRM_Hit_counter[i, 0]++;
                        results.IRM_Hit_counter[i, 1] += Convert.ToInt64(current_line[schema.fields["time-taken"]]);
                        if (results.IRM_Hit_counter[i, 2] < Convert.ToInt64(current_line[schema.fields["time-taken"]]))
                            results.IRM_Hit_counter[i, 2] = Convert.ToInt64(current_line[schema.fields["time-taken"]]);
                        break;
                    }
                }
                // Add to hourly accounting
                results.HOURLY_hit_counter[_hour, (int)constants.HOURLY_TABLE._invrulemgmt]++;

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
				output.AppendFormat("\t\"rx_bytes\" : {0}, \n", results.RX_BYTES.ToString());
				output.AppendFormat("\t\"tx_bytes\" : {0}, \n", results.TX_BYTES.ToString());
                output.Append("\t\"stats\" : {\n");

                // HOURLY STATS
                output.Append("\t\t\"hourly\" : [\n");
                output.Append("\t\t\t[\"Hour\", \"Total hit #\", \"Post Event\", \"Get Client Policy\", \"Get Pkg Info\", \"Speed test\", \"Task Mgmt\", \"Inv. Rule Mgmt\"],\n");
                for (int j = 0; j < 24; j++) {
						output.AppendFormat("\t\t\t[\"{0}\", {1}, {2}, {3}, {4}, {5}, {6}, {7}],\n", 
							j.ToString(),
							results.HOURLY_hit_counter[j, (long) constants.HOURLY_TABLE._total].ToString(),
							results.HOURLY_hit_counter[j, (long) constants.HOURLY_TABLE._postevent].ToString(),
							results.HOURLY_hit_counter[j, (long) constants.HOURLY_TABLE._packageinfo].ToString(),
							results.HOURLY_hit_counter[j, (long) constants.HOURLY_TABLE._getpolicies].ToString(),
							results.HOURLY_hit_counter[j, (long) constants.HOURLY_TABLE._connection_test].ToString(),
							results.HOURLY_hit_counter[j, (long) constants.HOURLY_TABLE._taskmgmt].ToString(),
							results.HOURLY_hit_counter[j, (long) constants.HOURLY_TABLE._invrulemgmt].ToString()
						);
                }
                output.Length = output.Length - 2; // Remove the last ",\n"
                output.AppendLine("\n\t\t],");

                // HOURLY RXTX STATS
                output.Append("\t\t\"hourly_rxtx\" : [\n");
                output.Append("\t\t\t[\"Hour\", \"RX Bytes\", \"TX Bytes\"],\n");
                for (int j = 0; j < 24; j++) {
						output.AppendFormat("\t\t\t[\"{0}\", {1}, {2}],\n", 
							j.ToString(),
							results.HOURLY_rxtx_counter[j, 0].ToString(),
							results.HOURLY_rxtx_counter[j, 1].ToString()
						);
                }
                output.Length = output.Length - 2; // Remove the last ",\n"
                output.AppendLine("\n\t\t],");


                // MIME TYPE STATS
                output.AppendFormat("\t\t\"mime_type\" : [\n");
                output.AppendFormat("\t\t\t[\"Mime type\", \"Hit #\"],\n");
                for (int j = 0; j < results.MIME_TYPE_hit_counter.Length; j++) {
					if (results.MIME_TYPE_hit_counter[j] > 0)
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
						output.AppendFormat("\t\t\t[\"{0}\", {1}, {2}, {3}, {4}],\n", constants.atrs_iis_vdir[j], results.WEBAPP_Hit_counter[j, 0].ToString(), results.WEBAPP_Hit_counter[j, 1].ToString(), results.WEBAPP_Hit_counter[j, 2].ToString(), FloatToDottedString(avg));
                    }
                }
                output.Length = output.Length - 2; // Remove the last ",\n"
                output.AppendLine("\n\t\t],");

                // HTTP Status code stats
                output.AppendFormat("\t\t\"http_status\" : [\n");
                output.AppendFormat("\t\t\t[\"Http-status\", \"Hit #\"],\n");
                for (int j = 0; j < 4; j++) {
					if (results.IIS_STATUS_hit_counter[j] > 0)
						output.AppendFormat("\t\t\t[\"{0}\", {1}],\n", constants.iis_status_code[j], results.IIS_STATUS_hit_counter[j].ToString());
                }
                output.Length = output.Length - 2; // Remove the last ",\n"
                output.Append("\n\t\t],\n");


                // AGENT INTERFACE STATS
				bool print_agent_interface = false;
                for (int j = 0; j < constants.atrs_agent_req.Length; j++) {
					if (results.AGENT_Hit_counter[j, 1] > 0) {
						print_agent_interface = true;
					}
				}
				if (print_agent_interface) {
					output.AppendFormat("\t\t\"agent_interface\" : [\n");
					output.AppendFormat("\t\t\t[\"Agent interface\", \"Hit #\", \"Sum(time-taken)\", \"Max(time-taken)\", \"Avg(time-taken)\"],\n");
					for (int j = 0; j < constants.atrs_agent_req.Length; j++) {
						float avg = 0;
						if (results.AGENT_Hit_counter[j, 1] > 0) {
							// Console.WriteLine("Calculation = {0} / {1}...", results.WEBAPP_Hit_counter[j, 2], results.WEBAPP_Hit_counter[j, 1]);
							avg = (float)results.AGENT_Hit_counter[j, 1] / (float)results.AGENT_Hit_counter[j, 0];
							output.AppendFormat("\t\t\t[\"{0}\", {1}, {2}, {3}, {4}],\n", constants.atrs_agent_req[j], results.AGENT_Hit_counter[j, 0].ToString(), results.AGENT_Hit_counter[j, 1].ToString(), results.AGENT_Hit_counter[j, 2].ToString(), FloatToDottedString(avg));
						}
					}
					output.Length = output.Length - 2; // Remove the last ",\n"
					output.Append("\n\t\t],\n");
				}

                // TASK MANAGEMENT INTERFACE STATS
				bool print_task_interface = false;
				for (int j = 0; j < constants.atrs_task_req.Length; j++) {
					if (results.TASK_Hit_counter[j, 1] > 0) {
						print_task_interface = true;
					}
				}
				if (print_task_interface) {
					output.AppendFormat("\t\t\"task_interface\" : [\n");
					output.AppendFormat("\t\t\t[\"Task interface\", \"Hit #\", \"Sum(time-taken)\", \"Max(time-taken)\", \"Avg(time-taken)\"],\n");
					for (int j = 0; j < constants.atrs_task_req.Length; j++) {
						float avg = 0;
						if (results.TASK_Hit_counter[j, 1] > 0) {
							avg = (float)results.TASK_Hit_counter[j, 1] / (float)results.TASK_Hit_counter[j, 0];
							output.AppendFormat("\t\t\t[\"{0}\", {1}, {2}, {3}, {4}],\n", 
								constants.json_task_req[j],
								results.TASK_Hit_counter[j, 0].ToString(),
								results.TASK_Hit_counter[j, 1].ToString(),
								results.TASK_Hit_counter[j, 2].ToString(),
								FloatToDottedString(avg));
						}
					}
					output.Length = output.Length - 2; // Remove the last ",\n"
					output.Append("\n\t\t],\n");
				}

                // INVENTORY RULE MANAGEMENT PARAM STATS
				bool print_irm_interface = false;
				for (int j = 0; j < constants.atrs_irm_params.Length; j++) {
					if (results.IRM_Hit_counter[j, 1] > 0) {
						print_irm_interface = true;
					}
				}
				if (print_irm_interface) {
					output.AppendFormat("\t\t\"invrule_interface\" : [\n");
					output.AppendFormat("\t\t\t[\"IRM AgentRuleData.ashx\", \"Hit #\", \"Sum(time-taken)\", \"Max(time-taken)\", \"Avg(time-taken)\"],\n");
					for (int j = 0; j < constants.atrs_irm_params.Length; j++) {
						float avg = 0;
						if (results.IRM_Hit_counter[j, 1] > 0) {
							// Console.WriteLine("Calculation = {0} / {1}...", results.WEBAPP_Hit_counter[j, 2], results.WEBAPP_Hit_counter[j, 1]);
							avg = (float)results.IRM_Hit_counter[j, 1] / (float)results.IRM_Hit_counter[j, 0];
							output.AppendFormat("\t\t\t[\"{0}\", {1}, {2}, {3}, {4}],\n",
								constants.json_irm_params[j],
								results.IRM_Hit_counter[j, 0].ToString(),
								results.IRM_Hit_counter[j, 1].ToString(),
								results.IRM_Hit_counter[j, 2].ToString(),
								FloatToDottedString(avg));
						}
					}
					output.Length = output.Length - 2; // Remove the last ",\n"
					output.Append("\n\t\t],");
				}

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
                output.AppendFormat("\t\t\t[\"IP Address\", \"Hit count\"],\n");

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
                    }
                }
                output.Length = output.Length - 2;

                // CLOSE THE JSON
                output.AppendLine("\n\t\t]\n\t}\n}");

                if (!config.out_path.EndsWith("\\")) {
                    config.out_path = config.out_path + "\\";
                }

                if (config.stdin) {
                    Console.WriteLine(output.ToString());
                } else {
                    SaveToFile(config.out_path + filename.Replace(".log", ".json"), output.ToString());
                    SaveToFile(config.out_path + filename.Replace(".log", ".txt"), results.IP_Handler.GetIpList());
                }
            }
        }

    }
    
    class constants {

        public enum HOURLY_TABLE {
            _total,
            _postevent,
            _packageinfo,
            _getpolicies,
			_connection_test,
            _taskmgmt,
            _invrulemgmt,
			_rxbytes,
			_txbytes
        };

        /******************************************************************************
         * Web-applications data (enum, match strings and JSON string)
         ******************************************************************************/
        public enum ATRS_IIS_VDIR {
	        _atrs_ns_agent,
	        _atrs_tm,		// TaskManagement
	        _atrs_ns,
			_atrs_ps,
	        _atrs_irm,		// InventoryRuleAgent
	        _atrs_resource,
	        _atrs_ns_nscap,
	        _atrs_packages,
	        _atrs_ps_share,
	        _atrs_swportal,
	        _atrs_cta,		// ClientTaskAgent
	        _atrs_cts,		// ClientTaskServer
	        _atrs_cnsl,		// 6.5, 7.x Console
	        _atrs_ac,
            _atrs_workflow,
            _atrs,
	        _other_vdir
        };

        public static readonly string [] atrs_iis_vdir = new string [] {
	        "/altiris/ns/agent/",
	        "/altiris/taskmanagement/",
	        "/altiris/ns/",
	        "/altiris/ps/",
	        "/altiris/inventoryrulemanagement/",
	        "/altiris/resource/",
	        "/altiris/ns/nscap/",
	        "/altiris/packageshare/",
	        "/altiris/ps/share",
	        "/altiris/swportal/",
	        "/altiris/clienttaskagent/",
	        "/altiris/clienttaskserver/",
	        "/altiris/console/",
            "/altiris/activitycenter/",
            "/altiris/workflow/",
	        "/altiris",
	        "other"
        };

        /******************************************************************************
         * Inventory Rule Management data (enum, match strings and JSON string)
         ******************************************************************************/
        public static readonly string[] atrs_irm_params = new string[] {
            "datatype=dataclasshash",
            "datatype=dataclassrulesummary",
            "datatype=rules",
            "datatype=dataclassrules"
        };

        public static readonly string[] json_irm_params = new string[] {
            "DataClassHash",
            "DCRuleSummary",
            "Rules",
            "DataclassRules",
            "Other"
        };

        /******************************************************************************
         * Task Management data (enum, match strings and JSON string)
         ******************************************************************************/
        public static readonly string[] atrs_task_req = new string[] {
			"clienttaskserver/gettaskitems.aspx",
			"clienttaskserver/gettasks.aspx",
			"clienttaskserver/postnotification.aspx",
			"clienttaskserver/poststatus.aspx",
			"clienttaskserver/register.aspx",
			"clienttaskserver/getcomputercount.aspx",
			"clienttaskserver/getserverstatus.aspx",

			"clienttask/reporttaskdata.aspx",
			"clienttask/authenticate.aspx",
			"clienttask/gettaskversion.aspx",
			"clienttask/refreshtaskservers.aspx",
			"clienttask/registertaskserver.aspx",
			"clienttask/getclientnetworkinformation.aspx",
			"clienttask/exectsmethod.aspx",

			"ctagent/getclienttaskservers.aspx",
			"ctagent/persistentsettings.aspx"
        };

        public static readonly string[] json_task_req = new string[] {
			"clienttaskserver/gettaskitems.aspx",
			"clienttaskserver/gettasks.aspx",
			"clienttaskserver/postnotification.aspx",
			"clienttaskserver/poststatus.aspx",
			"clienttaskserver/register.aspx",
			"clienttaskserver/getcomputercount.aspx",
			"clienttaskserver/getserverstatus.aspx",

			"clienttask/reporttaskdata.aspx",
			"clienttask/authenticate.aspx",
			"clienttask/gettaskversion.aspx",
			"clienttask/refreshtaskservers.aspx",
			"clienttask/registertaskserver.aspx",
			"clienttask/getclientnetworkinformation.aspx",
			"clienttask/exectsmethod.aspx",

			"ctagent/getclienttaskservers.aspx",
			"ctagent/persistentsettings.aspx",

            "Other"
        };
		
        /******************************************************************************
         * Altiris Agent data (enum, match strings and JSON string)
         ******************************************************************************/
        public enum ATRS_AGENT_REQ {
	        _post_event_asp,
	        _post_event_aspx,
            _get_client_policy,
	        _get_pkg_info,
	        _get_pkg_snapshot,
	        _create_resource,
	        _get_license_details,
			_connection_test,
			_get_server_cert,
			_get_site_server_info,
			_agent_download,
			_create_ext_package,
			_get_client_cert,
			_get_client_cert_mig,
	        _other_req
        };

        public static readonly string [] atrs_agent_req = new string [] {
			"postevent.asp",
			"postevent.aspx",
			"getclientpolicies.aspx",
			"getpackageinfo.aspx",
			"getpackagesnapshot.aspx",
			"createresource.aspx",
			"getlicensedetails.aspx",
			"connectiontest.asp",
			"getservercertificate.aspx",
			"getsiteserverinfo.aspx",
			"altirisagentdownload.aspx",
			"createexternalpackage.aspx",
			"getclientcertificate.aspx",
			"getclientcertificatemig.aspx",
			"other"
        };

        /******************************************************************************
         * Http Mime types enumeration
         * Standard html mime types found in a Notification Server
         ******************************************************************************/
        public static readonly string [] http_mime_type = new string []{
	        "htm", "html", "css", "js", "gif", "png", "jpg",	// Standard html mimes
	        "asp", "aspx", "asmx", "ascx", "axd", "ashx",		// Microsoft web-mimes
	        "xml",
			"dmg", "exe", "msi", "msp", "vbs", "pl", "sh", "cmd",	// Installation & scripts
			"Other"
        };

        /******************************************************************************
         * IIS Return codes
         ******************************************************************************/
        public enum IIS_STATUS_CODES {
	        _iis_success,
	        _iis_redirect,
	        _iis_client_error,
	        _iis_server_error
        };

        public static readonly string [] iis_status_code = new string [] {
	        "1xx,2xx Success",
	        "3xx Redirected",
	        "4xx Client error",
	        "5xx Server error"
        };

        /******************************************************************************
         * IIS Win32 Return codes
         ******************************************************************************/
        public enum IIS_WIN32_STATUS {
	        _win32_success,
	        _win32_other
        };
    }
}
