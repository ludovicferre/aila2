using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Symantec.CWoC {
    class aila2_filter {
        public static string file_path;
        public static int time_taken;
        public static bool exclude;
        public static bool include;
        public static string [] exclusion_filter;
        public static string [] inclusion_filter;

        static int Main(string[] args) {
            if (args.Length == 0) {
                return -1;
            } else {
                file_path = "";
                time_taken = 0;

                int i = 0;

                exclude = false;
                include = false;

                bool current_check = false;
                int argc = args.Length;
                while (i < argc) {
                    if (args[i] == "-f" || args[i] == "--file") {
                        if (argc > i + 1) {
                            file_path = args[++i];
                            current_check = true;
                            continue;
                        } else {
                            return 0;
                        }
                    }
                    if (args[i] == "-t" || args[i] == "--time-taken") {
                        try {
                            time_taken = Convert.ToInt32(args[++i]);
                            continue;
                        } catch {
                            return -1;
                        }
                    }
                    if (args[i] == "--exclusion-filter" || args[i] == "-x") {
                        exclude = true;
                        exclusion_filter = args[++i].Split(' ');
                    }
                    if (args[i] == "--inclusion-filter" || args[i] == "-i") {
                        include = true;
                        inclusion_filter = args[++i].Split(' ');
                    }
                    i++;
                }

                if (current_check == true) {
                    LogAnalyzer a = new LogAnalyzer();
                    a.AnalyzeFile();
                } else {
                    return -1;
                }
                return 0;
            }
        }

        class SchemaParser {
            public List<int> field_positions;

            public SchemaParser() {
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

            public void ParseSchemaString(string schema) {
                schema = schema.Substring(9).TrimEnd();

                    string[] fields = schema.Split(' ');
                    int l = 0;
                    foreach (string f in fields) {
                        int i = 0;
                        foreach (string s in SupportedFields) {
                            if (s == f) {
                                field_positions.Add(l);
                                // Console.WriteLine("We have a match for string {0} at position {1}.", s, l.ToString());
                                break;
                            }
                            i++;
                        }
                        l++;
                    }
                    int j = 0;
                    foreach (int k in field_positions) {
                        // Console.WriteLine("{0}-{1}: {2}", j.ToString(), k.ToString(), SupportedFields[j]);
                        j++;
                    }
            }

        }

        class LogAnalyzer {
            private SchemaParser schema;
            private string[] current_line;
            private int _timetaken;

            public LogAnalyzer() {
                current_line = new string[32];
            }

            public void AnalyzeFile() {
                string filepath = aila2_filter.file_path;
                schema = new SchemaParser();

                try {
                    using (StreamReader r = new StreamReader(filepath)) {
                        while (r.Peek() >= 0) {
                            AnalyzeLine(r.ReadLine());
                        }
                    }
                } catch {
                }
            }

            private void AnalyzeLine(string line) {
                line = line.ToLower();
                if (line.StartsWith("#")) {
                    if (line.StartsWith("#fields:")) {
                        schema.ParseSchemaString(line);
                    }
                    Console.WriteLine(line);
                    return;
                }

                // Tokenize the current line
                string[] row_data = line.ToLower().Split(' ');
                int i = 0;
                current_line.Initialize();

                foreach (int j in schema.field_positions) {
                    current_line[i] = row_data[j];
                    i++;
                }

                _timetaken = Convert.ToInt32(current_line[(int)SchemaParser.FieldPositions.timetaken]);
                if (_timetaken > aila2_filter.time_taken) {
                    if (exclude) {
                        foreach (string s in exclusion_filter) {
                            if (current_line[(int)SchemaParser.FieldPositions.uristem].Contains(s)) {
                                return;
                            }
                        }
                        if (!include) {
                            Console.WriteLine(line);
                        }
                    }
                    if (include) {
                        foreach (string s in inclusion_filter) {
                            if (current_line[(int)SchemaParser.FieldPositions.uristem].Contains(s)) {
                                Console.WriteLine(line);
                            }
                        }
                    }
                }
            }
        }
    }
}
