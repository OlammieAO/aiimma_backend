module.exports = {
    
"LoginID" : { required: true, type: "number"},
"UserRole" : { required: true, type: "string"},
"Logged_In_At" : { required: false, type: "date"},
"Logged_Out_At" : { required: false, type: "date"},
"Logged_In_Ip" : { required: false, type: "string"},
"Logged_Out_Ip" : { required: false, type: "string"},
"LoginTrackingToken" : { required: false, type: "string"},
"LogoutTrackingToken" : { required: false, type: "string"},
"RecordCreatedAt" : { required: true, type: "date"},
};

// allowed types - number, string, boolean, object, undefined
