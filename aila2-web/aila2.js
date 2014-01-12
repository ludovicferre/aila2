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


function hide(elem) {
	var e = document.getElementById(elem);
	e.className = "hide";
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
