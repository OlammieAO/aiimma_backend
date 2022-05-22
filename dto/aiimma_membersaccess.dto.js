module.exports = {
    
"login_id" : { required: true, type: "number"},
"Login_Role" : { required: true, type: "string"},
"Pwd" : { required: true, type: "string"},
"EmailID" : { required: true, type: "string"},
"emailValidated" : { required: true, type: "string"},
"emailActivationCode" : { required: false, type: "string"},
"PhoneNo" : { required: true, type: "string"},
"phoneValidated" : { required: true, type: "string"},
"phoneOneTimeValidationCode" : { required: false, type: "string"},
"phoneOneTimeValidationCodeSentAt" : { required: false, type: "date"},
"phoneOneTimeValidationCodeValidPeriod" : { required: false, type: "number"},
"phoneLoginValidationCode" : { required: false, type: "string"},
"loginValidationCodeSentAt" : { required: false, type: "date"},
"loginValidationCodeValidPeriod" : { required: false, type: "number"},
"RoleCode" : { required: true, type: "string"},
"LoginStatus" : { required: true, type: "string"},
"LoggedIP" : { required: true, type: "string"},
"RecorCreatedAt" : { required: true, type: "date"},
};

// allowed types - number, string, boolean, object, undefined
