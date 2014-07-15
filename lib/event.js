/*
 *
 * ToolName: Security Report Tool
 * File Purpose: Regiter ToolBox panel and GCLI commands
 * Author: PATIL Kailas
 * Code by: A V Minhaz
 *
 */
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
			case 'export': return exports.errorMessages.export; break;
			case 'SSL': return exports.errorMessages.ssl;break;
			case 'Mixed Content Blocker': return exports.errorMessages.mcb; break;
			case 'Content Security Policy': return exports.errorMessages.csp; break;
			case 'CSP': return exports.errorMessages.csp; break;
			case 'Insecure Password Field': return exports.errorMessages.ipf; break;
			case 'Invalid HSTS Headers': return exports.errorMessages.ihh; break;
			default: return 'Unknown error: ' +aCategory; break;
		}
	},
	log: function(aData) {
		var category = aData.category;
		var displayMessage = this._getErrorMessage(category);
		var message = aData.message;
		var link = aData.link;

		var document = this.document;
		var icon = document.createElement("img");
		icon.src = "./images/sec_report_icon.png";
		var content = document.createElement("div");

		var messageContent = document.createElement("div");
		messageContent.className = "message";
		messageContent.appendChild(icon);
		messageContent.innerHTML += displayMessage;

		var hiddenMessage = document.createElement("input");
		//hiddenMessage.value = (JSON.parse(message))['JavaScript Error'];
		hiddenMessage.setAttribute('readonly', 'true');
		//messageContent.appendChild(hiddenMessage);

		/**
		 * #todo: Add a listener to the link to open in new tab
		 */
		var linkContent = document.createElement("div");
		linkContent.className = "link";
		if (link != null)
			linkContent.innerHTML = "<a href='javascript: window.location.href = \"file://" +link +"\";' title='open file'>" +link +"</a>";	

		content.appendChild(messageContent);
		content.appendChild(linkContent);

		document.getElementsByClassName('console')[0].appendChild(content);
	},
	clear: function() {
		var document = this.document;
		document.getElementsByClassName('console')[0].innerHTML = '';
	}
};