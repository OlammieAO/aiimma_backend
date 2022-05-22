module.exports = {
    
"booking_id" : { required: true, type: "number"},
"bookingDate" : { required: true, type: "date"},
"bookingAmount" : { required: true, type: "number"},
"LoggedIP" : { required: true, type: "string"},
"RecordCreatedAt" : { required: true, type: "date"},
"RecordUpdatedAt" : { required: false, type: "date"},
};

// allowed types - number, string, boolean, object, undefined
