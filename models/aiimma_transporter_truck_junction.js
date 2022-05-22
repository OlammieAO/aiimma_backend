const {getRows, insertRow, updateRow, deleteRow} = require('../database/query');
var SqlString = require('sqlstring');

exports.find = async (offset, pageSize) => {
    const query = `SELECT  d.LoggedIP as ID_Value, t.* FROM aiimma_transporter_truck_junction t  join aiimma_transporter_truck_junction d on t.transporter_id = d.ID  LIMIT ?, ?`;
    return getRows(query,[offset,pageSize]);
}

exports.findById = async (ID) => {
    const query = `SELECT  d.LoggedIP as ID_Value, t.* FROM aiimma_transporter_truck_junction t  join aiimma_transporter_truck_junction d on t.transporter_id = d.ID  WHERE t.ID=? LIMIT 0,1`;
    return getRows(query,[ID]);
}

exports.insert = async (object) => {
    const query = `INSERT INTO aiimma_transporter_truck_junction set ?`;
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
    let query = `UPDATE aiimma_transporter_truck_junction SET ? WHERE ID= ?`;
    updateValues = updateValues.concat([ID])
    query = query.replace("?", updateKeys.join(","));
    const result = await updateRow(query, updateValues);
    return result ? this.findById(ID) : null;
}

exports.remove = async (ID) => {
    const query = `DELETE FROM aiimma_transporter_truck_junction Where ID= ? `;
    return deleteRow(query,[ID]);
}

exports.count = async () => {
    const query = `SELECT count(*) TotalCount FROM aiimma_transporter_truck_junction t  join aiimma_transporter_truck_junction d on t.transporter_id = d.ID  `;
    const result = await getRows(query);
    if (result && result[0] && result[0].TotalCount && result[0].TotalCount > 0) {
        return result[0].TotalCount;
    } else {
        return 0;
    }
}

exports.search = async (offset, pageSize, key) => {
    const query = `SELECT  d.LoggedIP as ID_Value, t.* FROM aiimma_transporter_truck_junction t  join aiimma_transporter_truck_junction d on t.transporter_id = d.ID  WHERE  LOWER(t.transporter_id) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.truck_id) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.truck_in_use) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.connection_started) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.connection_ended) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.PrimaryTruck) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.LoggedIP) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.RecordCreationAt) LIKE `+SqlString.escape('%'+key+'%')+` LIMIT ?, ?`;
    return getRows(query,[offset, pageSize]);
}

exports.searchCount = async (key) => {
    const query = `SELECT count(*) TotalCount FROM aiimma_transporter_truck_junction t  join aiimma_transporter_truck_junction d on t.transporter_id = d.ID  WHERE  LOWER(t.transporter_id) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.truck_id) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.truck_in_use) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.connection_started) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.connection_ended) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.PrimaryTruck) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.LoggedIP) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.RecordCreationAt) LIKE `+SqlString.escape('%'+key+'%')+` `;
    const result = await getRows(query);
    if (result && result[0] && result[0].TotalCount && result[0].TotalCount > 0) {
        return result[0].TotalCount;
    } else {
        return 0;
    }
}


exports.getByID = async (offset, pageSize, ID) => {
    const query = `SELECT  d.LoggedIP as ID_Value, t.* FROM aiimma_transporter_truck_junction t  join aiimma_transporter_truck_junction d on t.transporter_id = d.ID  WHERE t.ID= ? LIMIT ?, ?`;
    return getRows(query,[ID,offset,pageSize]);
}

exports.getByIDCount = async (key) => {
    const query = `SELECT count(*) TotalCount FROM aiimma_transporter_truck_junction t  join aiimma_transporter_truck_junction d on t.transporter_id = d.ID  WHERE t.ID= ?`;
    const result = await getRows(query,[ID,offset,pageSize]);
    if (result && result[0] && result[0].TotalCount && result[0].TotalCount > 0) {
        return result[0].TotalCount;
    } else {
        return 0;
    }
}
