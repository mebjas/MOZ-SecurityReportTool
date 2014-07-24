/*
 *
 * ToolName: Security Report Tool
 * File Purpose: Regiter ToolBox panel and GCLI commands
 * Author: PATIL Kailas
 * Code by: A V Minhaz
 * @this-code: maintains a data-structure to hold information about various security issues
 */

exports.info = {
	csp: {
		risk: "high",
		name: "Content Security Policy",
		overview: "This web page is missing the Content-Security-Policy header!",
		insight: "Lack of normal behavior policy for content loaded and executed by the web page and can be exploited by attackers to load or execute malicious injected content.",
		impact: "Successful exploitation will allow remote attackers to execute arbitrary code or steal sensitive information such as cookies, authentication token, etc., or bypass the authentication mechanism.",
		fix: "Use Content Security Policy header to protect your website's users from content injection attacks, such as Cross-Site Scripting. The UserCSP extension of Firefox is useful tool to find most compatible policy for a web page",
		reference: [
			{
				tag: "CSP 1.0 W3C Candidate Recommendation",
				link: "http://www.w3.org/TR/CSP/",
				category: "W3C"
			},
			{
				tag: "CSP 1.1 Editor's Draft",
				link: "https://dvcs.w3.org/hg/content-security-policy/raw-file/tip/csp-specification.dev.html",
				category: "W3C"
			},
			{
				tag: "",
				link: "https://people.mozilla.org/~bsterne/content-security-policy/",
				category: ""
			},
			{
				tag: "",
				link: "https://developer.mozilla.org/en-US/docs/Security/CSP/Introducing_Content_Security_Policy",
				category: ""
			},
			{
				tag: "",
				link: "http://en.wikipedia.org/wiki/Content_Security_Policy",
				category: ""
			},
			{
				tag: "",
				link: "https://addons.mozilla.org/en-us/firefox/addon/newusercspdesign/",
				category: ""
			}	
		]
	},
	ssl: {
		risk: "high",
		name: "SSL Certificate Error",
		overview: "SSL Certificates have expired for this page!",
		insight: "",
		impact: "",
		fix: "",
		reference: [
			{
				tag: "",
				link: "",
				category: ""
			}	
		]
	},
	mcb: {
		risk: "low",
		name: "Mixed Content Blocks",
		overview: "",
		insight: "",
		impact: "",
		fix: "",
		reference: [
			{
				tag: "",
				link: "",
				category: ""
			}	
		]
	},
	isp: {
		risk: "medium",
		name: "Insecure Password Fields",
		overview: "",
		insight: "",
		impact: "",
		fix: "",
		reference: [
			{
				tag: "",
				link: "",
				category: ""
			}	
		]
	},
	ihh: {
		risk: "low",
		name: "Invalid HSTS Headers",
		overview: "",
		insight: "",
		impact: "",
		fix: "",
		reference: [
			{
				tag: "",
				link: "",
				category: ""
			}	
		]
	},
	isc: {
		risk: "low",
		name: "Insecure Cookies",
		overview: "",
		insight: "",
		impact: "",
		fix: "",
		reference: [
			{
				tag: "",
				link: "",
				category: ""
			}	
		]
	},
	mhv: {
		risk: "low",
		name: "Missing HTTPs Version",
		overview: "",
		insight: "",
		impact: "",
		fix: "",
		reference: [
			{
				tag: "",
				link: "",
				category: ""
			}	
		]
	},
	mxf: {
		risk: "high",
		name: "Missing X-Frame-Option",
		overview: "",
		insight: "",
		impact: "",
		fix: "",
		reference: [
			{
				tag: "",
				link: "",
				category: ""
			}	
		]
	}
};