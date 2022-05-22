module.exports = {
    
"NotificationCode" : { required: true, type: "string"},
"MessageType" : { required: true, type: "string"},
"NotificationTo" : { required: true, type: "string"},
"Messages" : { required: true, type: "string"},
"Recipients" : { required: true, type: "string"},
"MessageDate" : { required: false, type: "string"},
"SentBy" : { required: false, type: "string"},
"LoggedIP" : { required: true, type: "string"},
"RecorCreatedAt" : { required: false, type: "date"},
};

// allowed types - number, string, boolean, object, undefined
