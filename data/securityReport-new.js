/*
 *
 * ToolName: Security Report Tool
 * File Purpose: Register ToolBox panel and GCLI commands
 * Author: PATIL Kailas
 *
 */
var secConsole = {
	clear: function(message) {
		document.getElementsByClassName('console')[0].innerHTML = '';
	}
};


function downloadSecurityReport() {
	var event = new CustomEvent("downloadReport-message");
	document.documentElement.dispatchEvent(event);

	// Logged to console from securityReportUI.js
}

function openSecurityReport() {
	var event = new CustomEvent("openSecReport-msg");
	document.documentElement.dispatchEvent(event);
}