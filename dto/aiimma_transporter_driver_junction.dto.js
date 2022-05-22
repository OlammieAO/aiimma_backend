module.exports = {
    
"transporter_id" : { required: true, type: "number"},
"driver_id" : { required: true, type: "number"},
"driver_still_active" : { required: false, type: "string"},
"connection_started" : { required: false, type: "date"},
"connection_ended" : { required: false, type: "date"},
"LoggedIP" : { required: true, type: "string"},
"RecordCreationAt" : { required: true, type: "date"},
};

// allowed types - number, string, boolean, object, undefined
