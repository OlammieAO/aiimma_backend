const {getRows, insertRow, updateRow, deleteRow} = require('../database/query');
var SqlString = require('sqlstring');

exports.find = async (offset, pageSize) => {
    const query = `SELECT  t.* FROM aiimma_drivers t  LIMIT ?, ?`;
    return getRows(query,[offset,pageSize]);
}

exports.findById = async (ID) => {
    const query = `SELECT  t.* FROM aiimma_drivers t  WHERE t.ID=? LIMIT 0,1`;
    return getRows(query,[ID]);
}

exports.insert = async (object) => {
    const query = `INSERT INTO aiimma_drivers set ?`;
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
    let query = `UPDATE aiimma_drivers SET ? WHERE ID= ?`;
    updateValues = updateValues.concat([ID])
    query = query.replace("?", updateKeys.join(","));
    const result = await updateRow(query, updateValues);
    return result ? this.findById(ID) : null;
}

exports.remove = async (ID) => {
    const query = `DELETE FROM aiimma_drivers Where ID= ? `;
    return deleteRow(query,[ID]);
}

exports.count = async () => {
    const query = `SELECT count(*) TotalCount FROM aiimma_drivers t  `;
    const result = await getRows(query);
    if (result && result[0] && result[0].TotalCount && result[0].TotalCount > 0) {
        return result[0].TotalCount;
    } else {
        return 0;
    }
}

exports.search = async (offset, pageSize, key) => {
    const query = `SELECT  t.* FROM aiimma_drivers t  WHERE  LOWER(t.UserID) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.FullName) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Gender) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.DateOfBirth) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Phone) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.WhatsApp) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Avatar) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.DLNumber) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.DLAvatar) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.HouseAddress) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.StateOfOrigin) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Nationality) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Email) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.LoggedIP) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.RecordCreatedAt) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.RecordUpdatedAt) LIKE `+SqlString.escape('%'+key+'%')+` LIMIT ?, ?`;
    return getRows(query,[offset, pageSize]);
}

exports.searchCount = async (key) => {
    const query = `SELECT count(*) TotalCount FROM aiimma_drivers t  WHERE  LOWER(t.UserID) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.FullName) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Gender) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.DateOfBirth) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Phone) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.WhatsApp) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Avatar) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.DLNumber) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.DLAvatar) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.HouseAddress) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.StateOfOrigin) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Nationality) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Email) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.LoggedIP) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.RecordCreatedAt) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.RecordUpdatedAt) LIKE `+SqlString.escape('%'+key+'%')+` `;
    const result = await getRows(query);
    if (result && result[0] && result[0].TotalCount && result[0].TotalCount > 0) {
        return result[0].TotalCount;
    } else {
        return 0;
    }
}


