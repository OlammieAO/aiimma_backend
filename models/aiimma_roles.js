const {getRows, insertRow, updateRow, deleteRow} = require('../database/query');
var SqlString = require('sqlstring');

exports.find = async (offset, pageSize) => {
    const query = `SELECT  t.* FROM aiimma_roles t  LIMIT ?, ?`;
    return getRows(query,[offset,pageSize]);
}

exports.findById = async (RoleCode) => {
    const query = `SELECT  t.* FROM aiimma_roles t  WHERE t.RoleCode=? LIMIT 0,1`;
    return getRows(query,[RoleCode]);
}

exports.insert = async (object) => {
    const query = `INSERT INTO aiimma_roles set ?`;
    const id = await insertRow(query, object);
    return id > 0 ;
}

exports.update = async (RoleCode, object) => {
    const updateKeys = [];
    let updateValues = [];
    for (const key in object) {
        updateKeys.push(`${key}=?`);
        updateValues.push(`${object[key]}`);
    }
    let query = `UPDATE aiimma_roles SET ? WHERE RoleCode= ?`;
    updateValues = updateValues.concat([RoleCode])
    query = query.replace("?", updateKeys.join(","));
    const result = await updateRow(query, updateValues);
    return result ? this.findById(RoleCode) : null;
}

exports.remove = async (RoleCode) => {
    const query = `DELETE FROM aiimma_roles Where RoleCode= ? `;
    return deleteRow(query,[RoleCode]);
}

exports.count = async () => {
    const query = `SELECT count(*) TotalCount FROM aiimma_roles t  `;
    const result = await getRows(query);
    if (result && result[0] && result[0].TotalCount && result[0].TotalCount > 0) {
        return result[0].TotalCount;
    } else {
        return 0;
    }
}

exports.search = async (offset, pageSize, key) => {
    const query = `SELECT  t.* FROM aiimma_roles t  WHERE  LOWER(t.RoleCode) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.RoleName) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Description) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.LoggedIP) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.RecordCreatedAt) LIKE `+SqlString.escape('%'+key+'%')+` LIMIT ?, ?`;
    return getRows(query,[offset, pageSize]);
}

exports.searchCount = async (key) => {
    const query = `SELECT count(*) TotalCount FROM aiimma_roles t  WHERE  LOWER(t.RoleCode) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.RoleName) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Description) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.LoggedIP) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.RecordCreatedAt) LIKE `+SqlString.escape('%'+key+'%')+` `;
    const result = await getRows(query);
    if (result && result[0] && result[0].TotalCount && result[0].TotalCount > 0) {
        return result[0].TotalCount;
    } else {
        return 0;
    }
}


