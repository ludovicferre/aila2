using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace Symantec.CWoC.aila2 {
    class Program {
        static void Main(string[] args) {
            if (args.Length > 0 && args[0] == "-f") {

                LogAnalyzer a = new LogAnalyzer();
                a.AnalyzeFile(args[1]);
            }
            else {
                return;
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
        int[] field_positions;

        public SchemaParser() {
            current_schema_string = "";
            field_positions = new int[10];
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
            schema = schema.Substring(9);
            if (schema != current_schema_string) {
                current_schema_string = schema;
                string[] fields = schema.Split(' ');
                foreach (string f in fields) {
                    int i = 0;
                    foreach (string s in SupportedFields) {
                        if (s == f) {
                            field_positions.Add(i);
                            //Console.WriteLine("{0}: {1}", i.ToString(), f);
                            break;
                        }
                        i++;
                    }
                }
                int j = 0;
                foreach (int i in field_positions) {
                    Console.WriteLine("{0}-{1}: {2}", j++.ToString(), i.ToString(), SupportedFields[i]);
                }
            }
            return 0;
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
            } catch {
            }
            Console.WriteLine("We have read {0} lines in {1} milli-seconds.", results.LineCount.ToString(), Timer.duration());
            Console.WriteLine("The file {0} has {1} schema definition and {2} data lines.", filename, results.SchemaDef, results.DataLines);
        }

        private void AnalyzeLine(string line) {
            if (line.StartsWith("#")) {
                if (line.StartsWith("#Fields:")) {
                    if (schema.current_schema_string == "" || schema.current_schema_string != line) {
                        schema.ParseSchemaString(line.ToLower());
                        results.SchemaDef++;
                    }
                    // Console.WriteLine(line);
                }
            } else {
                results.DataLines++;
            }
        }
    }
}
