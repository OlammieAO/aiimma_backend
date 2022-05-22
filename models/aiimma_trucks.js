const {getRows, insertRow, updateRow, deleteRow} = require('../database/query');
var SqlString = require('sqlstring');

exports.find = async (offset, pageSize) => {
    const query = `SELECT  t.* FROM aiimma_trucks t  LIMIT ?, ?`;
    return getRows(query,[offset,pageSize]);
}

exports.findById = async (ID) => {
    const query = `SELECT  t.* FROM aiimma_trucks t  WHERE t.ID=? LIMIT 0,1`;
    return getRows(query,[ID]);
}

exports.insert = async (object) => {
    const query = `INSERT INTO aiimma_trucks set ?`;
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
    let query = `UPDATE aiimma_trucks SET ? WHERE ID= ?`;
    updateValues = updateValues.concat([ID])
    query = query.replace("?", updateKeys.join(","));
    const result = await updateRow(query, updateValues);
    return result ? this.findById(ID) : null;
}

exports.remove = async (ID) => {
    const query = `DELETE FROM aiimma_trucks Where ID= ? `;
    return deleteRow(query,[ID]);
}

exports.count = async () => {
    const query = `SELECT count(*) TotalCount FROM aiimma_trucks t  `;
    const result = await getRows(query);
    if (result && result[0] && result[0].TotalCount && result[0].TotalCount > 0) {
        return result[0].TotalCount;
    } else {
        return 0;
    }
}

exports.search = async (offset, pageSize, key) => {
    const query = `SELECT  t.* FROM aiimma_trucks t  WHERE  LOWER(t.TruckName) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.TruckPlateNumber) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.TruckChasisNumber) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.TruckColor) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.TruckSize) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Truck_Avatar_Url) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.TruckMSSCheckStatus) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.TruckMSSApprovedCert_Avatar_URL) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.TruckMSSCertNumber) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.TruckMSSCertValidDuration) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.TruckOwnedBy) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.LoggedIP) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.RecordCreatedAt) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.RecordUpdatedAt) LIKE `+SqlString.escape('%'+key+'%')+` LIMIT ?, ?`;
    return getRows(query,[offset, pageSize]);
}

exports.searchCount = async (key) => {
    const query = `SELECT count(*) TotalCount FROM aiimma_trucks t  WHERE  LOWER(t.TruckName) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.TruckPlateNumber) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.TruckChasisNumber) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.TruckColor) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.TruckSize) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Truck_Avatar_Url) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.TruckMSSCheckStatus) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.TruckMSSApprovedCert_Avatar_URL) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.TruckMSSCertNumber) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.TruckMSSCertValidDuration) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.TruckOwnedBy) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.LoggedIP) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.RecordCreatedAt) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.RecordUpdatedAt) LIKE `+SqlString.escape('%'+key+'%')+` `;
    const result = await getRows(query);
    if (result && result[0] && result[0].TotalCount && result[0].TotalCount > 0) {
        return result[0].TotalCount;
    } else {
        return 0;
    }
}


