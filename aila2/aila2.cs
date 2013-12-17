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

        public SchemaParser() {
            current_schema_string = "";
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
        public void AnalyzeFile (string filename) {
            // Count lines
            ResultSet results = new ResultSet();
            SchemaParser schema = new SchemaParser();
            Timer.Init();
            try {
                using (StreamReader r = new StreamReader(filename)){
                    while (r.Peek() >= 0) {
                        string line = r.ReadLine();
                        if (line.StartsWith("#")) {
                            if (line.StartsWith("#Fields:")) {
                                if (schema.current_schema_string == "" || schema.current_schema_string != line) {
                                    schema.current_schema_string = line;
                                    results.SchemaDef++;
                                }
                                Console.WriteLine(line);
                            }
                        } else {
                            results.DataLines++;
                        }

                        results.LineCount++;
                    }
                }
            } catch {
            }
            Console.WriteLine("We have read {0} lines in {1} milli-seconds.", results.LineCount.ToString(), Timer.duration());
            Console.WriteLine("The file {0} has {1} schema definition and {2} data lines.", filename, results.SchemaDef, results.DataLines);
        }

        private void AnalyzeLine(string line) {

        }
    }
}
