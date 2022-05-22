const {getRows, insertRow, updateRow, deleteRow} = require('../database/query');
var SqlString = require('sqlstring');

exports.find = async (offset, pageSize) => {
    const query = `SELECT  z.LoggedIP as ID_Value, t.* FROM aiimma_booking_payments t  join aiima_transporter_driver_bthb_booking z on t.booking_id = z.ID  LIMIT ?, ?`;
    return getRows(query,[offset,pageSize]);
}

exports.findById = async (ID) => {
    const query = `SELECT  z.LoggedIP as ID_Value, t.* FROM aiimma_booking_payments t  join aiima_transporter_driver_bthb_booking z on t.booking_id = z.ID  WHERE t.ID=? LIMIT 0,1`;
    return getRows(query,[ID]);
}

exports.insert = async (object) => {
    const query = `INSERT INTO aiimma_booking_payments set ?`;
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
    let query = `UPDATE aiimma_booking_payments SET ? WHERE ID= ?`;
    updateValues = updateValues.concat([ID])
    query = query.replace("?", updateKeys.join(","));
    const result = await updateRow(query, updateValues);
    return result ? this.findById(ID) : null;
}

exports.remove = async (ID) => {
    const query = `DELETE FROM aiimma_booking_payments Where ID= ? `;
    return deleteRow(query,[ID]);
}

exports.count = async () => {
    const query = `SELECT count(*) TotalCount FROM aiimma_booking_payments t  join aiima_transporter_driver_bthb_booking z on t.booking_id = z.ID  `;
    const result = await getRows(query);
    if (result && result[0] && result[0].TotalCount && result[0].TotalCount > 0) {
        return result[0].TotalCount;
    } else {
        return 0;
    }
}

exports.search = async (offset, pageSize, key) => {
    const query = `SELECT  z.LoggedIP as ID_Value, t.* FROM aiimma_booking_payments t  join aiima_transporter_driver_bthb_booking z on t.booking_id = z.ID  WHERE  LOWER(t.booking_id) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.bookingDate) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.bookingAmount) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.LoggedIP) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.RecordCreatedAt) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.RecordUpdatedAt) LIKE `+SqlString.escape('%'+key+'%')+` LIMIT ?, ?`;
    return getRows(query,[offset, pageSize]);
}

exports.searchCount = async (key) => {
    const query = `SELECT count(*) TotalCount FROM aiimma_booking_payments t  join aiima_transporter_driver_bthb_booking z on t.booking_id = z.ID  WHERE  LOWER(t.booking_id) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.bookingDate) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.bookingAmount) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.LoggedIP) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.RecordCreatedAt) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.RecordUpdatedAt) LIKE `+SqlString.escape('%'+key+'%')+` `;
    const result = await getRows(query);
    if (result && result[0] && result[0].TotalCount && result[0].TotalCount > 0) {
        return result[0].TotalCount;
    } else {
        return 0;
    }
}


exports.getByID = async (offset, pageSize, ID) => {
    const query = `SELECT  z.LoggedIP as ID_Value, t.* FROM aiimma_booking_payments t  join aiima_transporter_driver_bthb_booking z on t.booking_id = z.ID  WHERE t.ID= ? LIMIT ?, ?`;
    return getRows(query,[ID,offset,pageSize]);
}

exports.getByIDCount = async (key) => {
    const query = `SELECT count(*) TotalCount FROM aiimma_booking_payments t  join aiima_transporter_driver_bthb_booking z on t.booking_id = z.ID  WHERE t.ID= ?`;
    const result = await getRows(query,[ID,offset,pageSize]);
    if (result && result[0] && result[0].TotalCount && result[0].TotalCount > 0) {
        return result[0].TotalCount;
    } else {
        return 0;
    }
}
