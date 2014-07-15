/*
 *
 * ToolName: Security Report Tool
 * File Purpose: Regiter ToolBox panel and GCLI commands
 * Author: PATIL Kailas
 *
 */

// Supplimentary function to change class of tab
function changeDirectiveClass(id, flag) {
	switch (id) {
		case 1:
			if (!flag)
				document.getElementById("csp").className = "";
			else
				document.getElementById("csp").className = "current";
			break;
		case 2:
			if (!flag)
				document.getElementById("insec-passwd").className = "";
			else
				document.getElementById("insec-passwd").className = "current";
			break;
		case 3:
			if (!flag)
				document.getElementById("mixed-content").className = "";
			else
				document.getElementById("mixed-content").className = "current";
			break;
		case 4:
			if (!flag)
				document.getElementById("ssl").className = "";
			else
				document.getElementById("ssl").className = "current";
			break;
		case 5:
			if (!flag)
				document.getElementById("sec-headers").className = "";
			else
				document.getElementById("sec-headers").className = "current";
			break;

	}
} // end of changeDirectiveClass() function

// Change log of tab contents
function changeReportLogs(evt, curTabId) {
	if (previousTabId === curTabId)
		return;

	// Remove "current" class from oldDirective
	changeDirectiveClass(previousTabId, false);
	// Set "current" class to currently selected tab
	changeDirectiveClass(curTabId, true);
	// Store curTabID for next reference
	previousTabId = curTabId;

	// Set textarea value to Empty
	document.getElementById('logTextarea').value = "";

	// window.postMessage("Message from page script", "Hello World!");

	var event = document.createEvent('CustomEvent');
	event.initCustomEvent("addon-message", true, true, curTabId);
	document.documentElement.dispatchEvent(event);

} // end of changeReportLogs() function

function downloadSecurityReport() {
	// var event = document.createEvent('CustomEvent');
	// event.initCustomEvent("downloadReport-message", true, true, "");
	var event = new CustomEvent("downloadReport-message");
	dump("\n\n About to dispatch custom event");
	document.documentElement.dispatchEvent(event);
} // end of downloadSecurityReport() function
