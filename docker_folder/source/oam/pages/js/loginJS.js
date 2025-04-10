/// Functions:

var isNav4 = false;
var isIE4 = false;
var isNS6 = false;
var showLang = true;
var endURL;
var backUrlParam = "";
var undef;
var sfaInterval;
var mypostrequest;


function detectBrowser() {
  if (navigator.appVersion.charAt(0) == "4") {
    if (navigator.appName == "Netscape") {
      isNav4 = true;
    } else {
      isIE4 = true;
    }
  } else if (navigator.appVersion.charAt(0) >= 5) {
    if (navigator.appName == "Netscape") {
      isNS6 = true;
    }
  }
}

function checkForEnterKey(event) {
  var keyChooser;
  if (isNav4 || isNS6) {
    keyChooser = event.which ;
  } else if (isIE4) {
    keyChooser = window.event.keyCode;
  }

  if (keyChooser == 13) { // 13 is code for enter-key
    if ( isNS6 != true ) // for FF, enter does implict submit
      logIn();
  }
}

function logIn() {
  if ( document.loginForm.userid.value == "" && disableJSPopup == false ) 	{
    alert(emptyUserName[ currentPageLang ]);
    return;
  }

  if ( document.loginForm.password.value == "" && disableJSPopup == false ) 	{
    alert(emptyPassword[ currentPageLang ]);
    return;
  }

  // This should be same as, action in form authn scheme
  document.loginForm.action = postActionURL; 
  document.loginForm.submit();
}

function registerUser() {
  registrationURL = registrationURL + ( registrationURL.indexOf("?") >= 0 ? "&" : "?");
  registrationURL = registrationURL  +  backUrlParam;
  window.location = registrationURL;
}

function trackUserRegistration() {
  window.location = trackRegistrationURL;
}

function lostPassword() {
  // For OIM lost Password, this has to be just a redirect, w/o any form data
  // This will be default behavior

   lostPasswordURL = lostPasswordURL + ( lostPasswordURL.indexOf("?") >= 0 ? "&" : "?");
   lostPasswordURL = lostPasswordURL  +  backUrlParam;
  
   if( isOIMLostPassword == true ) {
      window.location = lostPasswordURL ;
   }
  else {
  // For OAM lost Password, this has to be POST request, with login as form parameter

    if ( document.loginForm.userid.value == "" && disableJSPopup == false ) {
      alert(emptyUserName[ currentPageLang ]);
      return;
    }

    var newFormInput = document.createElement("input");
    newFormInput.setAttribute("name","login");
    newFormInput.setAttribute("type","hidden");
    newFormInput.setAttribute("value",document.loginForm.userid.value);
    document.loginForm.appendChild(newFormInput);

    document.loginForm.action = lostPasswordURL;
    document.loginForm.submit();
  }
}

function onBodyLoad() {
//  autoCompleteOff();
  detectBrowser();
  checkIfQueryString();
  // Hide Register Link for internal pages
  if ( hideRegLink == false ) {
    document.getElementById("registerLink").style.visibility="visible";
    document.getElementById("trackRegistrationLink").style.visibility="visible";
  }

  // Hide Simple Form
  var worldMapIcon = document.getElementById("languages1");
  if(worldMapIcon != null) {
   document.getElementById("languages1").style.visibility="hidden";

  }
//  var languageForm =  document.loginForm.Languages;

    var languageForm =  document.getElementById("Languages");
  if(languageForm != null) {
    // document.loginForm.Languages.style.visibility="hidden";
    document.getElementById("Languages").style.visibility="hidden";

  }
  //document.getElementById("languages").style.visibility="hidden";
  //document.loginForm.Languages.style.visibility="hidden";

  var langSelectionId = document.getElementById('displayLangSelectionId');
  if (langSelectionId != null && langSelectionId.value == 'true' ) {
    populateSimpleForm();
  }
}

function autoCompleteOff() {
  var passwordInput = document.loginForm.password;
  if(passwordInput != null) {
	  passwordInput.setAttribute("autocomplete", "off");
  }
}

function localeSelect() {

  var selectedIndx = document.getElementById("Languages").selectedIndex;
  var selectedOption = document.getElementById("Languages").options[selectedIndx];
  var selectedLang =document.getElementById("Languages").options[selectedIndx].value;
  var errorQueryParam = ''; // empty by default
  var undef;
  if ( isError != undef )
    errorQueryParam = "&errorpage=af";

  if (  backUrlParam  != "" )
    backUrlParam = "&" + backUrlParam;
  submitform();
 //window.location = loginRedirectScript + '?' + queryParamName + selectedLang +  backUrlParam  + errorQueryParam;
}
function contains(userLanguageArray, obj) {
    for (var i = 0; i < userLanguageArray.length; i++) {
        if (userLanguageArray[i] === obj) {
            return true;
        }
    }
    return false;
}
function populateSimpleForm() {

  var langIndx = 0;
  var doneSelect = false;
  var selectObject = document.getElementById("Languages");
  var worldMapIcon = document.getElementById("languages1");

//  var localeOption = document.createElement('Option');
//  localeOption.value = currentPageLang;
//  localeOption.text = selectLocale[ currentPageLang ];

//  try {
//    selectObject.add(localeOption, null);
//  }
//  catch(exception) {
//    selectObject.add(localeOption);
//  }

  //for(langIndx = 0; langIndx < displayLangs.length; langIndx++) {
    //localeOption = document.createElement('Option');
   // dispLang = displayLangs[langIndx];
   // localeOption.value = dispLang;
   // langIndx++;
    //localeOption.text = displayLangs[langIndx];

for(langIndx = 0; langIndx < displayLangs.length; langIndx++) {
	if( userLanguageArray.length==0 || contains(userLanguageArray,displayLangs[langIndx])){
		dispLang = displayLangs[langIndx];
		langIndx++;
		localeOption =new Option(displayLangs[langIndx],  dispLang);
		 selectObject.options[selectObject.options.length] = localeOption;
		var supLang = 0;
		if(showLang == true) {
		if(typeof(multiDimArray[ currentPageLang ]) == 'undefined'  || multiDimArray[ currentPageLang ] == null){
				multiDimArray[ currentPageLang ]= new Array(  'en' );    	
				}
		while( doneSelect == false && supLang < multiDimArray[ currentPageLang ].length ) {
		  if( doneSelect == false && dispLang == multiDimArray[ currentPageLang ][ supLang ] ) {
		localeOption.selected = "selected";
		doneSelect = true;
		  }
		supLang++;
		}
		}

	//    if(selectObject  != null ) {
	 //    try {
	   //  selectObject.add(localeOption, null);
		// }
		 //catch(exception) {
		 // selectObject.add(localeOption);
		 //}
		//}
	  }
}

  if(selectObject != null) {
    selectObject.style.visibility="visible";
  }
  if(worldMapIcon != null) {
    worldMapIcon.style.visibility="visible";
  }

}

function setCustomHeaderFooter() {

  var undef;
  if( helpLinkHREF != undef ) {
    var helpLink = document.getElementById("helpLink");
    if( helpLink != undef )
      helpLink.href = helpLinkHREF;
  }

  if( copyRightTEXT != undef ) {
    var copyRight = document.getElementById("copyRight");
    if( copyRight != undef )
      copyRight.innerHTML = copyRightTEXT;
  }

  if( appLogoIMAGE != undef && appLogoWIDTH != undef && appLogoHEIGHT != undef && appNameTEXT != undef ) {
    var appLogo = document.getElementById("appLogo");
    var appName = document.getElementById("appName");
    if( appName != undef ){
      var isCloud = document.getElementById("cloud");
      if(isCloud != null && isCloud.value == "true"){
      	    appName.innerHTML = appNameTEXT4Cloud;
    	}else{
      	    appName.innerHTML = appNameTEXT;
	}
     } 
 if( appLogo != undef ) {
      appLogo.src= appLogoIMAGE;
      appLogo.width = appLogoWIDTH;
      appLogo.height = appLogoHEIGHT;
    }
  }

  if( abtProduct != undef ) {
    var abtProductTag = document.getElementById("aboutProduct");
    if ( abtProductTag != undef )
      abtProductTag.href = abtProduct;
  }

  if( privacyPolicy != undef ) {
    var privacyPolicyTag = document.getElementById("privacyPolicy");
    if ( privacyPolicyTag != undef )
      privacyPolicyTag.href = privacyPolicy;
  }

  if( document.loginForm != undef && maxAllowedInputSize != undef ) {
    // Always do the following. This is required for allowing long usernames and passwords.
    document.loginForm.userid.maxLength = maxAllowedInputSize;
    document.loginForm.password.maxLength = maxAllowedInputSize;
  }
}

// Logout specific functions
function incrLoadedImages() {
  imagesLoaded = imagesLoaded + 1;
}

function loadLogoutImages() {
// Load images inline

  var imageLocation;
  for ( currentDomain = 0; currentDomain < maxImagesToLoad; currentDomain++ ) {
    imageLocation = callBackLocations[ currentDomain ] + "/access/logout.png ";
    document.writeln("<img src=" + imageLocation + " class=\"logoutimages\" alt=\".. \" onerror=\"javascript:incrLoadedImages();\" />");
  }
}

function waitAndRedirect() {
  var logoutMessage = document.getElementById('logoutInline');
  if (imagesLoaded >= maxImagesToLoad ) {
    logoutMessage.innerHTML = logoutSuccess[ currentPageLang ];
    checkIfEndURL();
    if( endURL != undef ) {
      var redirectAfterLogout = logoutRedirectScript + '?logout=done&' + endURL;
      window.location = redirectAfterLogout;
    } else {
      window.location = redirectToPage;
    }
  }
  else {
    logoutMessage.innerHTML = logoutFailed[ currentPageLang ];
  }
} 

function checkIfEndURL() {
  var queryString = window.location.search.substring(1);
  var queries = queryString.split('&');
  var testCounter = 0;
  for( testCounter = 0; testCounter < queries.length; testCounter++ )  {
    var string = queries[ testCounter ].toLowerCase();
    
    if( string.indexOf("end_url=") >= 0 ) {
      endURL = queryString;
    }
  }
}

function checkIfQueryString() {
  var queryString = window.location.search.substring(1);
  var queries = queryString.split('&');
  var testCounter = 0;
  showLang = true;
  backUrlParam = "";
  for( testCounter = 0; testCounter < queries.length; testCounter++ )  {
    var string = queries[ testCounter ];

    if( string.indexOf("backUrl=") >= 0 ) {
            backUrlParam = string;
     }
    else if( string.indexOf("showlang=") >= 0 ) {
            showLang = false;
     }
  }
}

function setFocusOnElement(elementId)
{
  var txtFieldDef = document.getElementById(elementId);
  if(txtFieldDef != null)
    txtFieldDef.focus();
}

function checkSfaStatus(sfaReqId,reqId,token,choice,sfaTypes){
document.loginForm.sfaReqId.value=sfaReqId;
document.loginForm.request_id.value=reqId;
if( token != ""){ 
document.loginForm.OAM_REQ.value=token;
}
var SFA_TYPE='';
var radios = document.getElementsByName(sfaTypes);
for (var i = 0, length = radios.length; i < length; i++) {
  if (radios[i].checked) {
       	SFA_TYPE=radios[i].value;
       	break;
    }
}//for
if(SFA_TYPE.length == 0){
  var choiceElem = document.getElementById(choice);
  if(typeof(choiceElem) != undefined && choiceElem != null) {	
	document.getElementById(choice).checked = true;
  }
}
document.loginForm.submit();
}

function unregister() {
  document.getElementById("removePswdless").value="true";
  document.loginForm.submit();
  return;
}

function consentBlock(getConsent) {
  if(document.getElementById("consent") != undefined) {
    if(getConsent = "consent") {
      document.getElementById("consent").style.display = "none";
    }
    else {
      document.getElementById("consent").style.display = "block";
    } 

  }
   
}

function sfaload(sfaParams,error,sendSuccess,sfaReqId,reqId,token,choice,sfaTypes,poll,errCode){
if(sfaParams == "null"){
	document.loginForm.submit();
	return;		
}else{
	document.getElementById("login").style.display="block";
}

if( sfaReqId != "" && error == "0"){
document.getElementById("optionData").style.display = "none";	
document.getElementById("loginData").style.display = "none";
if(document.getElementById("consent") != undefined) {
  document.getElementById("consent").style.display = "none";
}	
document.getElementById("sfawait").style.display = "block";
var SFA_TYPE='';
var radios = document.getElementsByName(sfaTypes);
for (var i = 0, length = radios.length; i < length; i++) {
  if (radios[i].checked) {
       	SFA_TYPE=radios[i].value;
       	break;
    }
}//lfor
if(SFA_TYPE.length == 0){
  var choiceElem = document.getElementById(choice);
  if(typeof(choiceElem) != undefined && choiceElem != null) {
	document.getElementById(choice).checked = true;
  }

}
sfaInterval=setTimeout(function(){checkSfaStatus(sfaReqId,reqId,token,choice,sfaTypes)},poll);

return;
} //if sfaReqId

if( error == "1" && sendSuccess == "false" ){
	document.getElementById("errorBar").style.display="block";
	document.getElementById("optionData").style.display = "block";	
	document.getElementById("loginData").style.display = "none";	
	document.getElementById("sfawait").style.display = "none";
	onBodyLoad();	
	return;			
}           

if(sendSuccess == "true" && error == "0" ){ 
        document.getElementById("errorBar").style.display="none";		 
	document.getElementById("sfawait").style.display = "none";
	document.getElementById("optionData").style.display = "none";	
	document.getElementById("loginData").style.display = "block";				
	onBodyLoad();	
	return;
}
if(sendSuccess == "true" && error == "1" ){
	document.getElementById("errorBar").style.display="block";
        if(SFA_TYPE != "PUSH" ) {
	document.getElementById("optionData").style.display = "none";		
	if(errCode == "MAX_ATTEMPTS") {
          document.getElementById("loginData").style.display = "none";
        } else {
	  document.getElementById("loginData").style.display = "block";
        }
        }
        else{
                document.getElementById("sfawait").style.display = "none";
        }
	onBodyLoad();	
	return;
}	

  // If there is there is less than two SFA options and the ByPassSfaOptionPage
  // value is not false, submit the form without displaying the options.
  if (sendSuccess == "null" && error == "0" ) {
    var sfaParamList = sfaParams.split(",");
    var byPassSfaOptionPage;
    for (var j = 0; j < sfaParamList.length; j += 1) {
      var pair = sfaParamList[j].split("=");
      if (pair[0] === "ByPassSfaOptionPage") {
        byPassSfaOptionPage = pair[1];
      }
    }
    // Checking "false" value because default value is true
    if (byPassSfaOptionPage != "false") {
      radios = document.getElementsByName(sfaTypes);
      if (radios.length < 2) {
        SFA_TYPE = radios[0].value;
        radios[0].checked = true;
        document.loginForm.sfaSSb.value = "true";
        document.getElementById("login").style.display = "none";
        document.loginForm.submit();
      }
    }
  }

}//function

 // Introduce this function to fix Bug 30120631 - SMS OTP PAGE REFRESH
 function showResults(params,option,pinEnabled){
  var SFA_TYPE='';
  var radios = document.getElementsByName(option);
  for (var i = 0, length = radios.length; i < length; i++) {
      if (radios[i].checked) {
          SFA_TYPE=radios[i].value;
          break;
            }
        }
  var pinIndex = params.indexOf(SFA_TYPE.concat(pinEnabled));

  var pinEnabled = params.substring(params.indexOf("=",pinIndex)+1,params.indexOf(",",pinIndex));

  document.loginForm.sfaSSb.value = "true";
  document.loginForm.submit();
  //setting the timeout to 3s and call showResult() and then render the page.
  setTimeout(function(){showResult(params,option,pinEnabled);},3000);
 }


  function showResult(params,option,pinEnabled) {
   var SFA_TYPE='';
	var radios = document.getElementsByName(option);
	for (var i = 0, length = radios.length; i < length; i++) {
	  if (radios[i].checked) {
        	SFA_TYPE=radios[i].value;
        	break;
	    }
	}
        var pinIndex = params.indexOf(SFA_TYPE.concat(pinEnabled));

	var pinEnabled = params.substring(params.indexOf("=",pinIndex)+1,params.indexOf(",",pinIndex));
					  
	if(SFA_TYPE.length > 0 && pinEnabled == "true"){ 
		document.getElementById("optionData").style.display = "none";
		document.getElementById("loginData").style.display = "block";
        
		}
	if(SFA_TYPE.length > 0 && pinEnabled == "false"){ 
		document.getElementById("optionData").style.display = "none";
		document.getElementById("loginData").style.display = "none";
	document.getElementById("sfawait").style.display = "block";
        
		}

	//document.loginForm.sfaSSb.value = "true";
	//if(SFA_TYPE !== "Totp"){
        //document.loginForm.submit();
        //}
}
				
function showOptions(){
	document.getElementById("errorBar").style.display="none";
	document.getElementById("optionData").style.display = "block";
	document.getElementById("loginData").style.display = "none";
} 



function loginSubmit(preValue,option){
 var SFA_TYPE='';
	var radios = document.getElementsByName(option);
	for (var i = 0, length = radios.length; i < length; i++) {
	  if (radios[i].checked) {
        	SFA_TYPE=radios[i].value;
        	break;
	    }
	}
if(SFA_TYPE.length == 0){
document.getElementById(preValue).checked = true;
}
document.loginForm.sfaSSb.value="false";
document.loginForm.submit();
}


function hideError(){
	document.getElementById("errorBar").style.display="none";
}
