/*
 *
 * ToolName: Security Report Tool
 * File Purpose: Regiter ToolBox panel and GCLI commands
 * Author: PATIL Kailas
 * Code by: A V Minhaz
 *
 */

// Add local logging module
const ds = require("info");

exports.errorMessages = {
	export: 'Report exported to file!',
	ssl: 'SSL Certificate Error observed on this page!',
	mcb: 'Mixed Contents were observed on this page!',
	csp: 'Content Security Voilations observed on this page!',
	ipf: 'Insecure Password Fields Observed on this page!',
	ihh: 'Invalid HSTS Headers observed on this page!'
};

// Constructor
exports.eventObj = {
	document: null,
	_init: function(reportUI) {
		this.document = reportUI.panelWin.document;
	},
	_getErrorMessage: function(aCategory) {
		switch(aCategory) {
			case 'export': return ''; break;
			case 'SSL': return 'ssl';break;
			case 'Mixed Content Blocker': return ''; break;
			case 'Content Security Policy': return 'csp'; break;
			case 'CSP': return 'csp'; break;
			case 'Insecure Password Field': return 'ipf'; break;
			case 'Invalid HSTS Headers': return 'ihh'; break;
			default: return ''; break;
		}
	},
	_getSeverety: function(aCategory) {
		return 'high';
	},
	log: function(aData) {
		var category = aData.category;
		var index = this._getErrorMessage(category);
		var message = aData.message;
		//var link = aData.link;

		var document = this.document;
		var content = document.createElement("div");
		content.className = "bleft";

		var content_message = document.createElement("div");

		if (typeof ds.info[index] == undefined) {
			// Push some info to the dsConsole
		}

		/** Create and append the [+] / [-] block **/
		var _min = document.createElement("span");
			_min.className = "min";
			_min.setAttribute("state", "min");
			_min.setAttribute("title", "View More");
			_min.innerHTML = " [+] ";

		content_message.appendChild(_min);

		/** Create and append the category + severety information **/
		var _category = document.createElement("span");
			_category.setAttribute("class", "category " +this._getSeverety(category));
			_category.innerHTML = (typeof ds.info[index].name == undefined) ? " Unknown " : ds.info[index].name;
		content_message.appendChild(_category);

		/** Create and append the overview of the security report **/
		var _overview = document.createElement("span");
			_overview.className = "overview";
			_overview.innerHTML = (typeof ds.info[index].overview == undefined) ? " Unknown " : ds.info[index].overview;
		content_message.appendChild(_overview);

		var _hidden = document.createElement("div");
			_hidden.className = "hidden";

			var __insight = document.createElement("div");
				__insight.className = "insight";
				__insight.innerHTML = "<span class=\"header\">Insight</span>";
				__insight.innerHTML += (typeof ds.info[index].insight == undefined 
					|| ds.info[index].insight == "") ? " Unknown " : ds.info[index].insight;
			_hidden.appendChild(__insight);

			var __impact = document.createElement("div");
				__impact.className = "impact";
				__impact.innerHTML = "<span class=\"header\">Impact</span>";
				__impact.innerHTML += (typeof ds.info[index].impact == undefined
					|| ds.info[index].impact == "") ? " Unknown " : ds.info[index].impact;
			_hidden.appendChild(__impact);

			var __fix = document.createElement("div");
				__fix.className = "fix";
				__fix.innerHTML = "<span class=\"header\">Fix</span>";
				__fix.innerHTML += (typeof ds.info[index].fix == undefined
					|| ds.info[index].fix == "") ? " Unknown " : ds.info[index].fix;
			_hidden.appendChild(__fix);

			var __reference = document.createElement("div");
				__reference.className = "reference";
				__reference.innerHTML = "<span class=\"header\">Reference</span>";
				if (typeof ds.info[index].reference != undefined) {
					var ___ref_ul = document.createElement("ul");
					for (var i = 0; i < ds.info[index].reference.length; i++) {

						if (ds.info[index].reference[i].link == "")
							return;

						var ____ref_li = document.createElement("li");
							____ref_li.innerHTML = "";

						if (ds.info[index].reference[i].category != "") {
							____ref_li.innerHTML += "[ " +ds.info[index].reference[i].category +" ] ";
						}

						if (ds.info[index].reference[i].tag != "") {
							____ref_li.innerHTML += ds.info[index].reference[i].tag +" : ";
						}

						if (ds.info[index].reference[i].link != "") {
							____ref_li.innerHTML += ds.info[index].reference[i].link;
						}

						___ref_ul.appendChild(____ref_li);
					};

					__reference.appendChild(___ref_ul);
				}
			_hidden.appendChild(__reference);

		content_message.appendChild(_hidden);
		content.appendChild(content_message);
		document.getElementsByClassName('console')[0].appendChild(content);
	},
	clear: function() {
		var document = this.document;
		document.getElementsByClassName('console')[0].innerHTML = '';
	}
};