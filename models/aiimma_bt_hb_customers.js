const {getRows, insertRow, updateRow, deleteRow} = require('../database/query');
var SqlString = require('sqlstring');

exports.find = async (offset, pageSize) => {
    const query = `SELECT  t.* FROM aiimma_bt_hb_customers t  LIMIT ?, ?`;
    return getRows(query,[offset,pageSize]);
}

exports.findById = async (ID) => {
    const query = `SELECT  t.* FROM aiimma_bt_hb_customers t  WHERE t.ID=? LIMIT 0,1`;
    return getRows(query,[ID]);
}

exports.insert = async (object) => {
    const query = `INSERT INTO aiimma_bt_hb_customers set ?`;
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
    let query = `UPDATE aiimma_bt_hb_customers SET ? WHERE ID= ?`;
    updateValues = updateValues.concat([ID])
    query = query.replace("?", updateKeys.join(","));
    const result = await updateRow(query, updateValues);
    return result ? this.findById(ID) : null;
}

exports.remove = async (ID) => {
    const query = `DELETE FROM aiimma_bt_hb_customers Where ID= ? `;
    return deleteRow(query,[ID]);
}

exports.count = async () => {
    const query = `SELECT count(*) TotalCount FROM aiimma_bt_hb_customers t  `;
    const result = await getRows(query);
    if (result && result[0] && result[0].TotalCount && result[0].TotalCount > 0) {
        return result[0].TotalCount;
    } else {
        return 0;
    }
}

exports.search = async (offset, pageSize, key) => {
    const query = `SELECT  t.* FROM aiimma_bt_hb_customers t  WHERE  LOWER(t.CustomerID) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.CompanyName) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.CompanyRegCertNo) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.CustomerType) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Address) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Phone) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.WhatsApp_Phone) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Email) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Website) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.NPA_Approved) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Customer_Logo_Avatar) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Company_Cert_Avatar) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.LoggedIP) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.RecordCreatedAt) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.RecordUpdatedAt) LIKE `+SqlString.escape('%'+key+'%')+` LIMIT ?, ?`;
    return getRows(query,[offset, pageSize]);
}

exports.searchCount = async (key) => {
    const query = `SELECT count(*) TotalCount FROM aiimma_bt_hb_customers t  WHERE  LOWER(t.CustomerID) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.CompanyName) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.CompanyRegCertNo) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.CustomerType) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Address) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Phone) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.WhatsApp_Phone) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Email) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Website) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.NPA_Approved) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Customer_Logo_Avatar) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Company_Cert_Avatar) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.LoggedIP) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.RecordCreatedAt) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.RecordUpdatedAt) LIKE `+SqlString.escape('%'+key+'%')+` `;
    const result = await getRows(query);
    if (result && result[0] && result[0].TotalCount && result[0].TotalCount > 0) {
        return result[0].TotalCount;
    } else {
        return 0;
    }
}


