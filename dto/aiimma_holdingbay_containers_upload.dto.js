module.exports = {
    
"bt_hb_customer_id" : { required: false, type: "number"},
"UploadCode" : { required: false, type: "string"},
"ShippingLine" : { required: true, type: "string"},
"ContainerMTU_Number" : { required: true, type: "string"},
"ContainerSize" : { required: true, type: "string"},
"ContainerSpec" : { required: false, type: "string"},
"LoggedIP" : { required: true, type: "string"},
"holdingbay_id" : { required: false, type: "number"},
"RecordCreatedAt" : { required: true, type: "date"},
};

// allowed types - number, string, boolean, object, undefined
