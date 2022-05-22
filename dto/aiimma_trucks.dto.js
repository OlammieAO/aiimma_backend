module.exports = {
    
"TruckName" : { required: false, type: "string"},
"TruckPlateNumber" : { required: false, type: "string"},
"TruckChasisNumber" : { required: false, type: "string"},
"TruckColor" : { required: false, type: "string"},
"TruckSize" : { required: true, type: "string"},
"Truck_Avatar_Url" : { required: false, type: "string"},
"TruckMSSCheckStatus" : { required: false, type: "string"},
"TruckMSSApprovedCert_Avatar_URL" : { required: false, type: "string"},
"TruckMSSCertNumber" : { required: false, type: "string"},
"TruckMSSCertValidDuration" : { required: false, type: "string"},
"TruckOwnedBy" : { required: false, type: "number"},
"LoggedIP" : { required: true, type: "string"},
"RecordCreatedAt" : { required: true, type: "date"},
"RecordUpdatedAt" : { required: false, type: "date"},
};

// allowed types - number, string, boolean, object, undefined
