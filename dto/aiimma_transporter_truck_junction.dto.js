module.exports = {
    
"transporter_id" : { required: true, type: "number"},
"truck_id" : { required: true, type: "number"},
"truck_in_use" : { required: false, type: "string"},
"connection_started" : { required: false, type: "date"},
"connection_ended" : { required: false, type: "date"},
"PrimaryTruck" : { required: true, type: "string"},
"LoggedIP" : { required: true, type: "string"},
"RecordCreationAt" : { required: false, type: "date"},
};

// allowed types - number, string, boolean, object, undefined
