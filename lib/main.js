var secConsole = {
	_allowedCategory: ['SSL', 'Mixed Content Blocker', 'Content Security Policy', 'CSP', 'Insecure Password Field', 'Invalid HSTS Headers'],
	_ignoreCategory: ['CSS Parser', 'chrome javascript', 'system javascript', 'FrameConstructor', 'content javascript'],
	_inCategory: function(aCategory) {
		var i = 0;
		for (; i < this._ignoreCategory.length; i++) {
			if (aCategory == this._ignoreCategory[i])
				return true;
		}
		return false;
	}
};


const {Cc,Ci,Cu} = require("chrome");

const xpcom = require("sdk/platform/xpcom");

try { Cu.import("resource://gre/modules/Services.jsm"); } catch (e) { }
try { Cu.import("resource://gre/modules/XPCOMUtils.jsm"); } catch (e) { }
try { Cu.import("resource://gre/modules/NetUtil.jsm"); } catch (e) { }

// Include our custom Modules
const securityReportUI = require("securityReportUI");
const secEvents = require("event");

/*
 * Code to intercept messages sent to Error Console (aka. Browser Console)
 */
var errorListener = {
		observe: function(aMessage) {
			try {
				// Get nsIScriptError object to retrieve "category" info of msg
				let error = aMessage.QueryInterface(Ci.nsIScriptError);
				if (error instanceof Ci.nsIScriptError) {
					if (!secConsole._inCategory(aMessage.category)) {
						
						dump("\n nsIScriptError found");
						//dump("\n Error = " +error);
						//dump ("\n aMessage = " + aMessage.message);
						dump(", category = " + aMessage.category +"\n");

						//Send captured message data for display in UI
						securityReportUI.displayErrorMsg(error, aMessage);
					}
				}
			} catch (e) {
				/*
				dump("\n\n nsISecurityConsoleMessage Doesn't exists in console service"
					+"\nError = " +e
					+"\n category = " +aMessage.category
					+"\n Message = " +aMessage.message);
				*/
			}
		}
};

// Register event listener for console message service to capture msg
var consoleService = Cc["@mozilla.org/consoleservice;1"].getService(Ci.nsIConsoleService);
consoleService.registerListener(errorListener);
  
/*
 * Observer registration on Security Errors and Warnings CSP observer event =
 * "csp-on-violate-policy" mixed-content observer event = "" SSL observer event = ""
 * CORS observer event = ""
 */
var ConsoleAPIObserver = {
  init: function init() {
   // dump("\n Init invoked!! \n");
   Services.obs.addObserver(this, "csp-on-violate-policy", false);
   Services.obs.addObserver(this, "security-console-message-received", false);
   // Services.obs.addObserver(this, "report-ssl-errors", false);
   // Services.obs.addObserver(this, "report-mixed-content", false);
  },  

  observe: function observe(aSubject, aTopic, aData) {
      if (aTopic === "csp-on-violate-policy") {
          // dump("\n aData = " + aData);
          var violatingResource = "";
          try {
              var uri = aSubject.QueryInterface(Ci.nsIURI);
              if (uri instanceof Ci.nsIURI) {
              	violatingResource = uri.asciiSpec;
               // dump("\n aSubject.data = " + violatingResource);
              }
          } catch (e) {
              // if that fails, the aSubject is probably a string
          		violatingResource = aSubject.QueryInterface(Ci.nsISupportsCString);
              // dump("\n aSubject is a STRING!!! str = "+ violatingResource +
							// "\n");
          }          
      } else if (aTopic === "security-console-message-received") {
    		aSubject = aSubject.QueryInterface(Ci.nsISecurityConsoleMessage);
    		// dump("\n\n\n lookupKey = " + aSubject.lookupKey);
    		// dump("\n category = " + aSubject.category);
    		// dump("\n aSubject.paramsLength = " + aSubject.paramsLength);
      } else if (aTopic === "report-ssl-errors") {
          // dump("\n\n aTopic = " + aTopic);
          // dump("\n aData = " + aData);
          // dump("\n aSubject = " + aSubject);
      } else if (aTopic === "report-mixed-content") {
          // dump("\n\n aTopic = " + aTopic);
          // dump("\n aData = " + aData);
          try {
              var uri = aSubject.QueryInterface(Ci.nsIURI);
              if (uri instanceof Ci.nsIURI) {
                  // dump("\n aSubject.data = " + uri.asciiSpec);
              }
          } catch (e) {
              // if that fails, the aSubject is probably a string
              var str = aSubject.QueryInterface(Ci.nsISupportsCString);
              // dump("\n aSubject is a STRING!!! str = "+ str + "\n");
          }
      } // end of "report-mixed-content"
  } // end of observer function
  
}; // end of consoleAPIObserver object
ConsoleAPIObserver.init();




/*
 * ConsoleMessage and observer notification interception code Ends here
 */
// -----------------------------------------------------------------------



/*
 * Code to add "Security Report" to Developer Tools Toolbox
 * 
 * Code References: https://developer.mozilla.org/en-US/docs/Tools/DevToolsAPI
 * https://developer.mozilla.org/en-US/docs/Social_API_Devtools
 * http://mxr.mozilla.org/mozilla-aurora/source/browser/devtools/framework/test/browser_toolbox_dynamic_registration.js
 */


// Register ToolBox Panel
securityReportUI.registerSecurityReportTool();


// --------------------------------------------------------------------
// Add-on Unload Routine
require("sdk/system/unload").when(function() { 
    // Unregister security report tool
    securityReportUI.securityReportToolUnregister();
});
// --------------------------------------------------------------------

