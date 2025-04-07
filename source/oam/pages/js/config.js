


//** SECTION A: THE PARAMETERS IN THIS SECTION CAN BE CHANGED TO SUIT THE DEPLOYMENT	**//
//** THE VARIABLES ARE INTENDED TO BE CONFIGURABLE PARAMETERS.					**//

// Parameter to specify OIM (OHS) Web Server Root used in URL for forgot password, registration etc.
// WebServer Root URL can start with either http:// or secure, https://
// For example, OimOHSHostPort = 'http://OIM-OHS-Host:Port'
var OimOHSHostPort = '';

// Parameter to specify estimated wait time in milliseconds for logout 
// processing to complete
var maxLogoutWaitTime = 1625;


// Parameter to specify comma separated list of WebServers. Only required 
// in multi-domain scenario. By default array is empty
// For example,
// var callBackLocations = new Array ( 'http://exampleone.com' , 'http://exampletwo.com' );
var callBackLocations = new Array ( );


// Parameter to specify default end URL
var redirectToPage = '/defaultendURL';				


// Parameter to specify Help, Product Info and Privacy Policy pages
// These pages should be unprotected
var abtProduct = "/abtProduct";
var helpLinkHREF = '/helpURL';
var privacyPolicy = "/privacyPolicy";




//** SECTION B: THE PARAMETERS IN THIS SECTION ARE SHIPPED WITH PRESET VALUES. THESE 	**//
//** PARAMETERS MAINLY CONTROL LOOK AND FEEL OF LOGIN PAGES. THESE PARAMETERS SHOULD 	**//
//** BE CHANGED TO SUIT THE DEPLOYMENT									**//


// Copyright information to display on login / logout pages
var copyRightTEXT; // = 'Copyright &copy; 2010, Oracle. All rights reserved.';

// Logo image to be used
var appLogoIMAGE = "/fusion_apps/global/images/oracle_logo.png";


// Other customization
var appNameTEXT = "Fusion Applications";        // Application Name ^M
var appNameTEXT4Cloud = "Public Cloud";	// Application Name in case of cloud 9 

var appLogoWIDTH = "119";			// Application Logo width
var appLogoHEIGHT = "25";			// Application Logo height

// Login Page locale settings
// Entries in this array are used as source for languages appearing in 
// Language Selection menu. On each line first value is language identifier 
// and other is name of language as it should appear in Languages Selection 
// Menu
// Changes to this array will be required, only if, support for certain 
// languages needs to be removed

var displayLangs = new Array (	'ar', 'Arabic - العربية ', 
				'cs', 'Czech - Čeština ', 
				'da', 'Danish - Dansk ',
				'de', 'German - Deutsch ',
				'el', 'Greek - Ελληνικά ',
				'en', 'English ',
				'es', 'Spanish - Español ',
				'fi', 'Finnish - suomi ',
				'fr-ca', 'French (Canada) - Français (Canada) ',
				'fr', 'French - Français ',
				'he', 'Hebrew - עברית ',
				'iw', 'Hebrew - עברית ',
				'hr', 'Croatian - Hrvatski ',
				'hu', 'Hungarian - Magyar ',
				'it', 'Italian - Italiano ',
				'ja', 'Japanese - 日本語',
				'ko', 'Korean - 한국어',
				'nl', 'Dutch - Nederlands ',
				'no', 'Norwegian - Norsk ',
				'pl', 'Polish - Polski ',
				'pt-br', 'Portuguese (Brazil) - Português (Brasil)',
				'pt', 'Portuguese - Português ',
				'ro', 'Romanian - Română ',
				'ru', 'Russian - Русский ',
				'sk', 'Slovak - Slovenčina ',
				'sv', 'Swedish - Svenska ',
				'th', 'Thai  ไทย ',
				'tr', 'Turkish Türkçe ',
				'zh-cn', 'Simplified Chinese 简体中文 ',
				'zh-tw', 'Traditional Chinese 繁體中文 ')



//** SECTION C: THE PARAMETERS IN THIS SECTION ARE SHIPPED WITH PRESET VALUES. THESE 	**//
//** PARAMETERS	SHOULD BE CHANGED ON NEED BASIS ONLY. 						**//

// Parameters to specify actual redirection URLs for forgot password, registration etc.
var registrationURL = OimOHSHostPort + '/oim/faces/pages/USelf.jspx?OP_TYPE=SELF_REGISTRATION&T_ID=Self-Register%20User&E_TYPE=USELF';

var lostPasswordURL = OimOHSHostPort + '/admin/faces/pages/forgotpwd.jspx';

var trackRegistrationURL = OimOHSHostPort + '/oim/faces/pages/USelf.jspx?E_TYPE=USELF&OP_TYPE=UNAUTH_TRACK_REQUEST';

// Page Layout Controls
var hideRegLink = true;		// Hide registration URL, true by default for internal deployments
var hideLocaleSelect = false;		// Hide Locale Selection menu, false by default
var disableJSPopup = true;		// Disable JavaScript popups, true by default
var maxAllowedInputSize = 200;	// Specify the max allowed userid and password field size

// Variables used in JavaScript for Form Authentication and Locale Selection to work
var isOIMLostPassword = true;				// Lost Password URL is OIM URL
var loginRedirectScript = '/cgi-bin/loginredirect.pl';  // Path to loginredirect.pl script on Authenticating WebGate WebServer
var logoutRedirectScript = '/cgi-bin/logout.pl';	// Path to logout.pl script on Authenticating WebGate WebServer
var postActionURL = '/oam/server/auth_cred_submit';			// OAM Form Login action POST URL, should match with Form Authentication Scheme
var queryParamName = 'selected=';			// Query Parameter used to propagate locale selction by User

// Logout processing related parameters
var maxImagesToLoad = callBackLocations.length;
var imagesLoaded = 0;

// Array of language name variations
var multiDimArray = new Array();
multiDimArray[ 'ar' ] = new Array(  'ar' );
multiDimArray[ 'cs' ] = new Array(  'cs' );
multiDimArray[ 'da' ] = new Array(  'da' );
multiDimArray[ 'de' ] = new Array(  'de' );
multiDimArray[ 'el' ] = new Array(  'el' );
multiDimArray[ 'en' ] = new Array(  'en' );
multiDimArray[ 'es' ] = new Array(  'es' );
multiDimArray[ 'fi' ] = new Array(  'fi' );
multiDimArray[ 'fr-ca' ] = new Array(  'fr-ca' );
multiDimArray[ 'fr' ] = new Array(  'fr' );
multiDimArray[ 'he' ] = new Array(  'he' );
multiDimArray[ 'hr' ] = new Array(  'hr' );
multiDimArray[ 'hu' ] = new Array(  'hu' );
multiDimArray[ 'it' ] = new Array(  'it' );
multiDimArray[ 'ja' ] = new Array(  'ja' );
multiDimArray[ 'ko' ] = new Array(  'ko' );
multiDimArray[ 'nl' ] = new Array(  'nl' );
multiDimArray[ 'no' ] = new Array(  'no' );
multiDimArray[ 'pl' ] = new Array(  'pl' );
multiDimArray[ 'pt-br' ] = new Array(  'pt-br' );
multiDimArray[ 'pt' ] = new Array(  'pt' );
multiDimArray[ 'ro' ] = new Array(  'ro' );
multiDimArray[ 'ru' ] = new Array(  'ru' );
multiDimArray[ 'sk' ] = new Array(  'sk' );
multiDimArray[ 'sv' ] = new Array(  'sv' );
multiDimArray[ 'th' ] = new Array(  'th' );
multiDimArray[ 'tr' ] = new Array(  'tr' );
multiDimArray[ 'zh-cn' ] = new Array(  'zh-cn' );
multiDimArray[ 'zh-tw' ] = new Array(  'zh-tw' );
multiDimArray[ 'iw' ] = new Array(  'iw' );

