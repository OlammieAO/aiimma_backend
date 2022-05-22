const {getRows, insertRow, updateRow, deleteRow} = require('../database/query');
var SqlString = require('sqlstring');

exports.find = async (offset, pageSize) => {
    const query = `SELECT  x.RoleName as RoleCode_Value, t.* FROM aiimma_staffs t  join aiimma_roles x on t.staffRole = x.RoleCode  LIMIT ?, ?`;
    return getRows(query,[offset,pageSize]);
}

exports.findById = async (id) => {
    const query = `SELECT  x.RoleName as RoleCode_Value, t.* FROM aiimma_staffs t  join aiimma_roles x on t.staffRole = x.RoleCode  WHERE t.id=? LIMIT 0,1`;
    return getRows(query,[id]);
}

exports.insert = async (object) => {
    const query = `INSERT INTO aiimma_staffs set ?`;
    const id = await insertRow(query, object);
    return id > 0 ;
}

exports.update = async (id, object) => {
    const updateKeys = [];
    let updateValues = [];
    for (const key in object) {
        updateKeys.push(`${key}=?`);
        updateValues.push(`${object[key]}`);
    }
    let query = `UPDATE aiimma_staffs SET ? WHERE id= ?`;
    updateValues = updateValues.concat([id])
    query = query.replace("?", updateKeys.join(","));
    const result = await updateRow(query, updateValues);
    return result ? this.findById(id) : null;
}

exports.remove = async (id) => {
    const query = `DELETE FROM aiimma_staffs Where id= ? `;
    return deleteRow(query,[id]);
}

exports.count = async () => {
    const query = `SELECT count(*) TotalCount FROM aiimma_staffs t  join aiimma_roles x on t.staffRole = x.RoleCode  `;
    const result = await getRows(query);
    if (result && result[0] && result[0].TotalCount && result[0].TotalCount > 0) {
        return result[0].TotalCount;
    } else {
        return 0;
    }
}

exports.search = async (offset, pageSize, key) => {
    const query = `SELECT  x.RoleName as RoleCode_Value, t.* FROM aiimma_staffs t  join aiimma_roles x on t.staffRole = x.RoleCode  WHERE  LOWER(t.staffCode) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.staffName) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Email) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Phone) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Gender) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.staffRole) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.RecordCreatedBy) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.LoggedIP) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.RecordCreatedAt) LIKE `+SqlString.escape('%'+key+'%')+` LIMIT ?, ?`;
    return getRows(query,[offset, pageSize]);
}

exports.searchCount = async (key) => {
    const query = `SELECT count(*) TotalCount FROM aiimma_staffs t  join aiimma_roles x on t.staffRole = x.RoleCode  WHERE  LOWER(t.staffCode) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.staffName) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Email) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Phone) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Gender) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.staffRole) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.RecordCreatedBy) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.LoggedIP) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.RecordCreatedAt) LIKE `+SqlString.escape('%'+key+'%')+` `;
    const result = await getRows(query);
    if (result && result[0] && result[0].TotalCount && result[0].TotalCount > 0) {
        return result[0].TotalCount;
    } else {
        return 0;
    }
}


exports.getByRolecode = async (offset, pageSize, RoleCode) => {
    const query = `SELECT  x.RoleName as RoleCode_Value, t.* FROM aiimma_staffs t  join aiimma_roles x on t.staffRole = x.RoleCode  WHERE t.RoleCode= ? LIMIT ?, ?`;
    return getRows(query,[RoleCode,offset,pageSize]);
}

exports.getByRolecodeCount = async (key) => {
    const query = `SELECT count(*) TotalCount FROM aiimma_staffs t  join aiimma_roles x on t.staffRole = x.RoleCode  WHERE t.RoleCode= ?`;
    const result = await getRows(query,[RoleCode,offset,pageSize]);
    if (result && result[0] && result[0].TotalCount && result[0].TotalCount > 0) {
        return result[0].TotalCount;
    } else {
        return 0;
    }
}
