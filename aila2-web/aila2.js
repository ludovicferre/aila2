/* request parameter getter */
function get_query_string() {
	// This function is anonymous, is executed immediately and
	// the return value is assigned to QueryString!
	var query_string = {};
	var query = window.location.search.substring(1);
	var vars = query.split("&");
	for (var i=0;i<vars.length;i++) {
		var pair = vars[i].split("=");
		// If first entry with this name
		if (typeof query_string[pair[0]] === "undefined") {
			query_string[pair[0]] = pair[1];
			// If second entry with this name
		} else if (typeof query_string[pair[0]] === "string") {
			var arr = [ query_string[pair[0]], pair[1] ];
			query_string[pair[0]] = arr;
			// If third or later entry with this name
		} else {
			query_string[pair[0]].push(pair[1]);
		}
	}
	return query_string;
}

/* Array helper functions */
function deep_copy(obj) {
	if (Object.prototype.toString.call(obj) === '[object Array]') {
		var out = [], i = 0, len = obj.length;
		for ( ; i < len; i++ ) {
			out[i] = arguments.callee(obj[i]);
		}
		return out;
	}
	if (typeof obj === 'object') {
		var out = {}, i;
		for ( i in obj ) {
			out[i] = arguments.callee(obj[i]);
		}
		return out;
	}
	return obj;
}

function arrayAllZero(array) {
	var allZero = true;
	for (var i = 1; i < array.length; i++) {
		var row = array[i];
		for (var j = 1; j < row.length; j++) {
			if (row[j] != 0)
				allZero = false;
		}
	}
	return allZero;
}

function removeEmptyRows(array) {
	for (var i = 1; i < array.length; i++) {
		if (array[i][1] == 0) {
			array.splice(i, 1);
			i--;
		}
	}
}

function sort_th(table) {
	head = deep_copy(table);
	head.splice(1, head.length - 1);
	table.shift();
	table.sort();
	return head.concat(table);
}

function reverse_th(table) {
	head = deep_copy(table);
	head.splice(1, head.length - 1);
	table.shift();
	table.reverse();
	return head.concat(table);
}

/* Hide element by switching its class */
function hide(elem) {
	var e = document.getElementById(elem);
	e.className = "hide";
}

/* Date handling functions */
function get_shortdate(filename) {
	var year;
	var month;
	var day;

	if (filename.startsWith("u_ex")) {
		// Sample: u_ex130411.json
		year = 2000 + parseInt(filename.substring(4, 6));
		month = filename.substring(6, 8);
		day = filename.substring(8, 10);
	} else if (filename.startsWith("ex")) {
		// Sample: ex130324.json
		year = 2000 + parseInt(filename.substring(2, 4));
		month = filename.substring(4, 6);
		day = filename.substring(6, 8);
	}

	return String(year) + "-" + String(month) + "-" + String(day);
}

function get_date(filename) {
	var year;
	var month;
	var day;

	if (filename.startsWith("u_ex")) {
		// Sample: u_ex130411.json
		year = 2000 + parseInt(filename.substring(4, 6));
		month = filename.substring(6, 8);
		day = filename.substring(8, 10);
	} else if (filename.startsWith("ex")) {
		// Sample: ex130324.json
		year = 2000 + filename.substring(3, 5);
		month = filename.substring(5, 7);
		day = filename.substring(7, 9);
	}

	return new Date(year, month -1, day);
}

function get_dayString(day) {
	var weekday =new Array("Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday");
	return weekday[day];
}

function get_dayInt(filename) {
	var date = get_date(filename);
	return date.getDay();
}
