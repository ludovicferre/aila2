using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class filter {
	public static string file_path;
	public static int time_taken;
	public static bool exclude;
	public static bool include;
	public static string[] exclusion_filter;
	public static string[] inclusion_filter;
	public static string filter_type;
	public static bool short_output;

	#region public static string HELP_MESSAGE
	public static string HELP_MESSAGE = @"
Usage: aila2-filter [options]

Options:

-f, --file          The path to the IIS log file you want to filter. This
			field is optional.

-t, --time-taken n  Filter on request that are taking long n milli-
					seconds. This only works if the IIS schema contains
					the time-taken field.

--type <column>     The filter inclusion and / or exclusion string will be
					used against the specified column. If not specified we
					use the URI Stem. Here are the supported columns:
					 ___________________________________________________
					| Column  | IIS field    |  Comment                 |
					|---------|--------------|--------------------------|
					| uri     | cs-uri-stem  |  The requested file path |
					| param   | cs-uri-query |  Request parameters      |
					| cip     | c-ip         |  Client IP address       |
					| status  | sc-status    |  IIS status code         |
					 ---------------------------------------------------

-i, --inclusion-filter ""filter string""

					Filter the IIS log file to include all request that
					match the entries provided in the filter string. The
					filter string is a list of space seperated entries.
					Each entry will be checked against the uri-stem field
					and matching entries will be printed out.

-x, --exclusion-filter ""filter string""

					Filter the IIS log file to exclude all request that
					match the entries provided in the filter string. The
					filter string is a list of space seperated entries.
					Each entry will be checked against the uri-stem field
					and matching entries will not be printed out.
					
-s, --short         This option control the output formatting. If selected
					the output log file will only contain the following
					fields (and any other fields will be discarded):
					
						date
						time-taken
						cs-method
						cs-uri-stem
						cs-uri-query
						cs-username
						c-ip
						sc-status
						sc-substatus
						sc-win32-status
						time-taken

If no file is specified the input will be read from the console (stdin).

If no arguments are specified this help message will be shown, as we expect at
least one of the 3 filters to be set (if you need to print a file to stdout you
can use type) or the --short option.

Note! The 3 filter are cascaded, which has some implication on what data will 
be displayed. Here is a detail explanation of the proceedings:

Stage 1: time-taken entries are matched. If nothing is specified by the 
user we use 0 as base. Entries greater or equal to the specified time-taken 
are passed on to the next filtering level.

Stage 2: exclusion entries are matched. Any match from the exclusion filter
will not be printed out or passed on to the next level. If no exclusion 
filters are defined the entries are passed on to the next level.

Stage 3: inclusion entries are matched. Any match from the inclusion filter
will be printed to stdout, miss will be discarded. If inclusion filters are
not defined all entries received at this level are printed to stdout.

Samples:

aila2-filter.exe -f u_ex131231.log -t 5000 -x ""itemservices.aspx console.
asmx"" -i ""console""

This filter will display all console operations but the itemservices and 
web-services hits (that are generated by the browser and not indicative of
user operation).

aila2-filter.exe -f u_ex131231.log -i ""inventoryrule postevent""

This filter will output all post event data and inventory rule data to 
stdout

aila2-filter.exe -f u_ex131231.log -t 10000 -x ""altiris/ns/agent"" > 
u_ex131231_5000ms.log

Output all requests outside of the NS/Agent uri that took longer than .5
seconds to complete and write the output to file u_ex131231_5000ms.log.

";
	#endregion

	static int Main(string[] args) {
		if (args.Length == 0) {
			Console.WriteLine(HELP_MESSAGE);
			return -1;
		} else { // Initialize the generic arguments to safe values;
			file_path = "";
			filter_type = "uri";
			time_taken = 0;
			exclude = false;
			include = false;
			short_output = false;

			if (args.Length == 1) {
				#region // Handle case when 1 argument alone is provided
				if (args[0] == "-v" || args[0] == "--version") {
					Console.WriteLine("aila2-filter version 2.");
					return 0;
				}
				Console.WriteLine(HELP_MESSAGE);
				if (args[0] == "/?" || args[0] == "--help") {
					return 0;
				} else {
					return -1;
				}
				#endregion
				#region // Handle standard arguments cases and process
			} else {
				file_path = "";
				time_taken = 0;

				int valid_args = 0;
				int argc = args.Length;
				int i = 0;

				for (int j = 0; j < argc; j++) {
					args[j] = args[j].ToLower();
				}

				while (i < argc) {
					if (args[i] == "-f" || args[i] == "--file") {
						if (argc > i) {
							file_path = args[++i];
							valid_args += 2;
							continue;
						} else {
							return -1;
						}
					}
					if (args[i] == "--type") {
						/* Handle filter types here. Supported types are:
						   - uri
						   - param
						   - cip
						   - status
						   - time-taken
						 */
						if (argc > i) {
							filter_type = args[++i];
							valid_args += 2;
						}
					}
					if (args[i] == "-s" || args[i] == "--short") {
						short_output = true;
						valid_args++;
					}
					if (args[i] == "-t" || args[i] == "--time-taken") {
						try {
							time_taken = Convert.ToInt32(args[++i]);
							valid_args += 2;
							continue;
						} catch {
							return -1;
						}
					}
					if (args[i] == "--exclusion-filter" || args[i] == "-x") {
						exclude = true;
						exclusion_filter = args[++i].Split(' ');
						valid_args += 2;
					}
					if (args[i] == "--inclusion-filter" || args[i] == "-i") {
						include = true;
						inclusion_filter = args[++i].Split(' ');
						valid_args += 2;
					}
					i++;
				}

				if (valid_args == argc) {
					LogAnalyzer a = new LogAnalyzer();
					if (file_path != "") {
						a.AnalyzeFile();
					} else {
						while (!a.AnalyzeStdin(Console.ReadLine()))
							;
						return 0;
					}
				} else {
					Console.WriteLine("We validated {0} arguments for {1} arguments provided.", valid_args, argc);
					Console.WriteLine(HELP_MESSAGE);
					return -1;
				}
			}
				#endregion
			return 0;
		}
	}

	public static readonly string[] SupportedFields = new string[] {
			"date", "time", "cs-method", "cs-uri-stem", "cs-uri-query", "cs-username", "c-ip", "sc-status", "sc-substatus", "sc-win32-status", "time-taken"
	};

	public enum f_pos { //Field Positions
		date = 0, time, method, uristem, uriquery, username, ip, status, substatus, win32status, timetaken
	}

	class SchemaParser {
		public List<int> field_positions;
		public bool ready;

		public SchemaParser() {
			field_positions = new List<int>();
			ready = false;
		}

		public void ParseSchemaString(string schema) {
			schema = schema.Substring(9).TrimEnd();
			string[] fields = schema.Split(' ');

			int l = 0;
			field_positions.Clear();
			foreach (string f in fields) {
				int i = 0;
				foreach (string s in SupportedFields) {
					if (s == f) {
						field_positions.Add(l);
						break;
					}
					i++;
				}
				l++;
			}
			if (field_positions.Count > 0) {
				ready = true;
			}
		}
	}

	class LogAnalyzer {
		private static SchemaParser schema;
		private string[] current_line;
		private int _timetaken;

		public LogAnalyzer() {
			current_line = new string[32];
			schema = new SchemaParser();
		}

		public void AnalyzeFile() {
			string filepath = filter.file_path;
			try {
				using (StreamReader r = new StreamReader(filepath)) {
					while (r.Peek() >= 0) {
						AnalyzeLine(r.ReadLine());
					}
				}
			} catch (Exception e){
				Console.Error.WriteLine(e.Message);
			}
		}

		public bool AnalyzeStdin(string line) {
			if (line == null) {
				return true;
			}
			try {
				AnalyzeLine(line);
			} catch (Exception e) {
				Console.Error.WriteLine(current_line);
				Console.Error.WriteLine(e.Message);
				return true; //Terminate process on input error
			}
			return false;
		}

		private void AnalyzeLine(string line) {
			line = line.ToLower();
			if (line.StartsWith("#")) { //Handle commented lines as this is were the schema is defined
				if (line.StartsWith("#fields:")) {
					schema.ParseSchemaString(line);
					if (short_output) {
						print_schema();
					} else {
						print(ref line);
					}
				} else {
					print(ref line);
				}
				return;
			}

			if (!schema.ready) {
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

			if (output_line()) {
				if (short_output) {
					print(ref row_data);
				} else {
					print(ref line);
				}
			}
		}

		public bool output_line() {
			_timetaken = Convert.ToInt32(current_line[(int)f_pos.timetaken]);
			if (_timetaken >= filter.time_taken) {
				if (!include && !exclude) {
					return true;
				}
				if (exclude) {
					foreach (string s in exclusion_filter) {
						if (line_matched(s)) {
							return false;
						}
					}
					if (!include) {
						return true;
					}
				}
				if (include) {
					foreach (string s in inclusion_filter) {
						if (line_matched(s)) {
							return true;
						}
					}
					return false;
				}
			}
			return false;
		}

		private bool line_matched(string s) {
			switch (filter_type) {
				case "uri":
					if (current_line[(int)f_pos.uristem].Contains(s)) {
						return true;
					}
					break;
				case "param":
					if (current_line[(int)f_pos.uriquery].Contains(s)) {
						return true;
					}
					break;
				case "cip":
					if (current_line[(int)f_pos.ip].Contains(s)) {
						return true;
					}
					break;
				case "status":
					if (current_line[(int)f_pos.status].Contains(s)) {
						return true;
					}
					break;
			}
			return false;
		}

		public static void print(ref string line) {
			Console.WriteLine(line);
		}

		public static void print(ref string[] data) {
			foreach (int j in schema.field_positions) {
				Console.Write(data[j] + ' ');
			}
			Console.WriteLine();
		}

		public static void print_schema() {
			Console.Write("#Fields: ");
			int j = 0;
			foreach (int k in schema.field_positions) {
				Console.Write(SupportedFields[j++] + ' ');
			}
			Console.WriteLine();
		}
	}
}
