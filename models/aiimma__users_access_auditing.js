const {getRows, insertRow, updateRow, deleteRow} = require('../database/query');
var SqlString = require('sqlstring');

exports.find = async (offset, pageSize) => {
    const query = `SELECT  cccc.Logged_In_Ip as ID_Value, t.* FROM aiimma__users_access_auditing t  join aiimma__users_access_auditing cccc on t.LoginID = cccc.ID  LIMIT ?, ?`;
    return getRows(query,[offset,pageSize]);
}

exports.findById = async (ID) => {
    const query = `SELECT  cccc.Logged_In_Ip as ID_Value, t.* FROM aiimma__users_access_auditing t  join aiimma__users_access_auditing cccc on t.LoginID = cccc.ID  WHERE t.ID=? LIMIT 0,1`;
    return getRows(query,[ID]);
}

exports.insert = async (object) => {
    const query = `INSERT INTO aiimma__users_access_auditing set ?`;
    const id = await insertRow(query, object);
    return id > 0 ;
}

exports.update = async (ID, object) => {
    const updateKeys = [];
    let updateValues = [];
    for (const key in object) {
        updateKeys.push(`${key}=?`);
        updateValues.push(`${object[key]}`);
    }
    let query = `UPDATE aiimma__users_access_auditing SET ? WHERE ID= ?`;
    updateValues = updateValues.concat([ID])
    query = query.replace("?", updateKeys.join(","));
    const result = await updateRow(query, updateValues);
    return result ? this.findById(ID) : null;
}

exports.remove = async (ID) => {
    const query = `DELETE FROM aiimma__users_access_auditing Where ID= ? `;
    return deleteRow(query,[ID]);
}

exports.count = async () => {
    const query = `SELECT count(*) TotalCount FROM aiimma__users_access_auditing t  join aiimma__users_access_auditing cccc on t.LoginID = cccc.ID  `;
    const result = await getRows(query);
    if (result && result[0] && result[0].TotalCount && result[0].TotalCount > 0) {
        return result[0].TotalCount;
    } else {
        return 0;
    }
}

exports.search = async (offset, pageSize, key) => {
    const query = `SELECT  cccc.Logged_In_Ip as ID_Value, t.* FROM aiimma__users_access_auditing t  join aiimma__users_access_auditing cccc on t.LoginID = cccc.ID  WHERE  LOWER(t.LoginID) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.UserRole) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Logged_In_At) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Logged_Out_At) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Logged_In_Ip) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Logged_Out_Ip) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.LoginTrackingToken) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.LogoutTrackingToken) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.RecordCreatedAt) LIKE `+SqlString.escape('%'+key+'%')+` LIMIT ?, ?`;
    return getRows(query,[offset, pageSize]);
}

exports.searchCount = async (key) => {
    const query = `SELECT count(*) TotalCount FROM aiimma__users_access_auditing t  join aiimma__users_access_auditing cccc on t.LoginID = cccc.ID  WHERE  LOWER(t.LoginID) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.UserRole) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Logged_In_At) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Logged_Out_At) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Logged_In_Ip) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Logged_Out_Ip) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.LoginTrackingToken) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.LogoutTrackingToken) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.RecordCreatedAt) LIKE `+SqlString.escape('%'+key+'%')+` `;
    const result = await getRows(query);
    if (result && result[0] && result[0].TotalCount && result[0].TotalCount > 0) {
        return result[0].TotalCount;
    } else {
        return 0;
    }
}


exports.getByID = async (offset, pageSize, ID) => {
    const query = `SELECT  cccc.Logged_In_Ip as ID_Value, t.* FROM aiimma__users_access_auditing t  join aiimma__users_access_auditing cccc on t.LoginID = cccc.ID  WHERE t.ID= ? LIMIT ?, ?`;
    return getRows(query,[ID,offset,pageSize]);
}

exports.getByIDCount = async (key) => {
    const query = `SELECT count(*) TotalCount FROM aiimma__users_access_auditing t  join aiimma__users_access_auditing cccc on t.LoginID = cccc.ID  WHERE t.ID= ?`;
    const result = await getRows(query,[ID,offset,pageSize]);
    if (result && result[0] && result[0].TotalCount && result[0].TotalCount > 0) {
        return result[0].TotalCount;
    } else {
        return 0;
    }
}
