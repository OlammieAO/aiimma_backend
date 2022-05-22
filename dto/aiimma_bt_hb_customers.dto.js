module.exports = {
    
"CustomerID" : { required: true, type: "string"},
"CompanyName" : { required: true, type: "string"},
"CompanyRegCertNo" : { required: false, type: "string"},
"CustomerType" : { required: false, type: "string"},
"Address" : { required: false, type: "string"},
"Phone" : { required: false, type: "string"},
"WhatsApp_Phone" : { required: false, type: "string"},
"Email" : { required: false, type: "string"},
"Website" : { required: false, type: "string"},
"NPA_Approved" : { required: true, type: "string"},
"Customer_Logo_Avatar" : { required: false, type: "string"},
"Company_Cert_Avatar" : { required: false, type: "string"},
"LoggedIP" : { required: true, type: "string"},
"RecordCreatedAt" : { required: true, type: "date"},
"RecordUpdatedAt" : { required: false, type: "date"},
};

// allowed types - number, string, boolean, object, undefined
