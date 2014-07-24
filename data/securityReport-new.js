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

function testCSP() {
	var event = new CustomEvent("test-csp");
	document.documentElement.dispatchEvent(event);	
}

$(document).ready(function() {
	$(document).on('click', '.min', function() {
		var state = $(this).attr("state");
		if (state == 'min') {
			// Means maximise it;
			$(this).next().next().next('.hidden').slideDown();
			$(this).html(' [-] ');
			$(this).attr('title', 'View Less');
			$(this).attr('state', 'max');
		} else {
			// Means minimize it;
			$(this).next().next().next('.hidden').slideUp();
			$(this).html(' [+] ');
			$(this).attr('title', 'View More');
			$(this).attr('state', 'min');
		}
	});
});