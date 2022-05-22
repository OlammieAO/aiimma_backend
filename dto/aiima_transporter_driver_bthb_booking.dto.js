module.exports = {
    
"BookingCode" : { required: true, type: "number"},
"JourneyCode" : { required: false, type: "string"},
"Transporter_id" : { required: false, type: "number"},
"Driver_id" : { required: false, type: "number"},
"bt_hb_customer_id" : { required: false, type: "number"},
"Truck_id" : { required: false, type: "number"},
"Container_MTU_No" : { required: false, type: "string"},
"Container_Size" : { required: false, type: "string"},
"Location_From" : { required: false, type: "string"},
"Journey_Destination_Port" : { required: false, type: "string"},
"Booking_Journey_Type" : { required: false, type: "string"},
"Booking_Category" : { required: false, type: "string"},
"JourneyStartedDate" : { required: false, type: "date"},
"ExpectedDeliveryDate" : { required: false, type: "date"},
"LockBooking" : { required: false, type: "string"},
"TruckStayDuration" : { required: false, type: "number"},
"BookingStatus" : { required: false, type: "string"},
"CallCardAvatar" : { required: false, type: "string"},
"CallCardUploadedAt" : { required: false, type: "date"},
"LoggedIP" : { required: true, type: "string"},
"RecordCreatedAt" : { required: true, type: "date"},
"RecordUpdatedAt" : { required: false, type: "date"},
};

// allowed types - number, string, boolean, object, undefined
