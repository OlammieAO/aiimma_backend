module.exports = {
    
"TDOGeneralCode" : { required: false, type: "string"},
"TDOIndividualCode" : { required: false, type: "string"},
"ShippingLine" : { required: true, type: "string"},
"ContainerNumber" : { required: true, type: "string"},
"Tonage" : { required: true, type: "string"},
"TonageDetails" : { required: false, type: "string"},
"Destination" : { required: true, type: "string"},
"DestinationDetails" : { required: false, type: "string"},
"ServiceStatus" : { required: false, type: "string"},
"LoggedIP" : { required: true, type: "string"},
"UploadedBy" : { required: false, type: "string"},
"User_Uploaded_ID" : { required: false, type: "number"},
"RecordCreatedAt" : { required: true, type: "date"},
};

// allowed types - number, string, boolean, object, undefined
