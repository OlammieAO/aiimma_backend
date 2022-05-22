const {getRows, insertRow, updateRow, deleteRow} = require('../database/query');
var SqlString = require('sqlstring');

exports.find = async (offset, pageSize) => {
    const query = `SELECT  ggg.UserID as ID_Value, v.RoleName as RoleCode_Value, t.* FROM aiimma_membersaccess t  join aiimma_transporters ggg on t.login_id = ggg.ID  join aiimma_roles v on t.RoleCode = v.RoleCode  LIMIT ?, ?`;
    return getRows(query,[offset,pageSize]);
}

exports.findById = async (ID) => {
    const query = `SELECT  ggg.UserID as ID_Value, v.RoleName as RoleCode_Value, t.* FROM aiimma_membersaccess t  join aiimma_transporters ggg on t.login_id = ggg.ID  join aiimma_roles v on t.RoleCode = v.RoleCode  WHERE t.ID=? LIMIT 0,1`;
    return getRows(query,[ID]);
}

exports.insert = async (object) => {
    const query = `INSERT INTO aiimma_membersaccess set ?`;
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
    let query = `UPDATE aiimma_membersaccess SET ? WHERE ID= ?`;
    updateValues = updateValues.concat([ID])
    query = query.replace("?", updateKeys.join(","));
    const result = await updateRow(query, updateValues);
    return result ? this.findById(ID) : null;
}

exports.remove = async (ID) => {
    const query = `DELETE FROM aiimma_membersaccess Where ID= ? `;
    return deleteRow(query,[ID]);
}

exports.count = async () => {
    const query = `SELECT count(*) TotalCount FROM aiimma_membersaccess t  join aiimma_transporters ggg on t.login_id = ggg.ID  join aiimma_roles v on t.RoleCode = v.RoleCode  `;
    const result = await getRows(query);
    if (result && result[0] && result[0].TotalCount && result[0].TotalCount > 0) {
        return result[0].TotalCount;
    } else {
        return 0;
    }
}

exports.search = async (offset, pageSize, key) => {
    const query = `SELECT  ggg.UserID as ID_Value, v.RoleName as RoleCode_Value, t.* FROM aiimma_membersaccess t  join aiimma_transporters ggg on t.login_id = ggg.ID  join aiimma_roles v on t.RoleCode = v.RoleCode  WHERE  LOWER(t.login_id) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Login_Role) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Pwd) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.EmailID) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.emailValidated) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.emailActivationCode) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.PhoneNo) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.phoneValidated) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.phoneOneTimeValidationCode) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.phoneOneTimeValidationCodeSentAt) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.phoneOneTimeValidationCodeValidPeriod) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.phoneLoginValidationCode) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.loginValidationCodeSentAt) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.loginValidationCodeValidPeriod) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.RoleCode) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.LoginStatus) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.LoggedIP) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.RecorCreatedAt) LIKE `+SqlString.escape('%'+key+'%')+` LIMIT ?, ?`;
    return getRows(query,[offset, pageSize]);
}

exports.searchCount = async (key) => {
    const query = `SELECT count(*) TotalCount FROM aiimma_membersaccess t  join aiimma_transporters ggg on t.login_id = ggg.ID  join aiimma_roles v on t.RoleCode = v.RoleCode  WHERE  LOWER(t.login_id) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Login_Role) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Pwd) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.EmailID) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.emailValidated) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.emailActivationCode) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.PhoneNo) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.phoneValidated) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.phoneOneTimeValidationCode) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.phoneOneTimeValidationCodeSentAt) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.phoneOneTimeValidationCodeValidPeriod) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.phoneLoginValidationCode) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.loginValidationCodeSentAt) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.loginValidationCodeValidPeriod) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.RoleCode) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.LoginStatus) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.LoggedIP) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.RecorCreatedAt) LIKE `+SqlString.escape('%'+key+'%')+` `;
    const result = await getRows(query);
    if (result && result[0] && result[0].TotalCount && result[0].TotalCount > 0) {
        return result[0].TotalCount;
    } else {
        return 0;
    }
}


exports.getByID = async (offset, pageSize, ID) => {
    const query = `SELECT  ggg.UserID as ID_Value, v.RoleName as RoleCode_Value, t.* FROM aiimma_membersaccess t  join aiimma_transporters ggg on t.login_id = ggg.ID  join aiimma_roles v on t.RoleCode = v.RoleCode  WHERE t.ID= ? LIMIT ?, ?`;
    return getRows(query,[ID,offset,pageSize]);
}

exports.getByIDCount = async (key) => {
    const query = `SELECT count(*) TotalCount FROM aiimma_membersaccess t  join aiimma_transporters ggg on t.login_id = ggg.ID  join aiimma_roles v on t.RoleCode = v.RoleCode  WHERE t.ID= ?`;
    const result = await getRows(query,[ID,offset,pageSize]);
    if (result && result[0] && result[0].TotalCount && result[0].TotalCount > 0) {
        return result[0].TotalCount;
    } else {
        return 0;
    }
}
exports.getByRolecode = async (offset, pageSize, RoleCode) => {
    const query = `SELECT  ggg.UserID as ID_Value, v.RoleName as RoleCode_Value, t.* FROM aiimma_membersaccess t  join aiimma_transporters ggg on t.login_id = ggg.ID  join aiimma_roles v on t.RoleCode = v.RoleCode  WHERE t.RoleCode= ? LIMIT ?, ?`;
    return getRows(query,[RoleCode,offset,pageSize]);
}

exports.getByRolecodeCount = async (key) => {
    const query = `SELECT count(*) TotalCount FROM aiimma_membersaccess t  join aiimma_transporters ggg on t.login_id = ggg.ID  join aiimma_roles v on t.RoleCode = v.RoleCode  WHERE t.RoleCode= ?`;
    const result = await getRows(query,[RoleCode,offset,pageSize]);
    if (result && result[0] && result[0].TotalCount && result[0].TotalCount > 0) {
        return result[0].TotalCount;
    } else {
        return 0;
    }
}
