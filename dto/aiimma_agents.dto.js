module.exports = {
    
"UserID" : { required: true, type: "string"},
"FullName" : { required: true, type: "string"},
"Email" : { required: false, type: "string"},
"Phone" : { required: false, type: "string"},
"Whatsapp" : { required: false, type: "string"},
"OfficeAddress" : { required: false, type: "string"},
"Avatar" : { required: false, type: "string"},
"IDType" : { required: false, type: "string"},
"IDNumber" : { required: false, type: "string"},
"IDAvatar" : { required: false, type: "string"},
"LoggedIP" : { required: true, type: "string"},
"RecordCreatedAt" : { required: true, type: "date"},
"RecordUpdatedAt" : { required: false, type: "date"},
};

// allowed types - number, string, boolean, object, undefined
