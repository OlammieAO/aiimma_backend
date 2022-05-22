const {getRows, insertRow, updateRow, deleteRow} = require('../database/query');
var SqlString = require('sqlstring');

exports.find = async (offset, pageSize) => {
    const query = `SELECT  iiii.LoggedIP as ID_Value, t.* FROM aiimma_truck_maintenance_journey_booking_details t  join aiima_transporter_driver_bthb_booking iiii on t.bookingid = iiii.ID  LIMIT ?, ?`;
    return getRows(query,[offset,pageSize]);
}

exports.findById = async (id) => {
    const query = `SELECT  iiii.LoggedIP as ID_Value, t.* FROM aiimma_truck_maintenance_journey_booking_details t  join aiima_transporter_driver_bthb_booking iiii on t.bookingid = iiii.ID  WHERE t.id=? LIMIT 0,1`;
    return getRows(query,[id]);
}

exports.insert = async (object) => {
    const query = `INSERT INTO aiimma_truck_maintenance_journey_booking_details set ?`;
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
    let query = `UPDATE aiimma_truck_maintenance_journey_booking_details SET ? WHERE id= ?`;
    updateValues = updateValues.concat([id])
    query = query.replace("?", updateKeys.join(","));
    const result = await updateRow(query, updateValues);
    return result ? this.findById(id) : null;
}

exports.remove = async (id) => {
    const query = `DELETE FROM aiimma_truck_maintenance_journey_booking_details Where id= ? `;
    return deleteRow(query,[id]);
}

exports.count = async () => {
    const query = `SELECT count(*) TotalCount FROM aiimma_truck_maintenance_journey_booking_details t  join aiima_transporter_driver_bthb_booking iiii on t.bookingid = iiii.ID  `;
    const result = await getRows(query);
    if (result && result[0] && result[0].TotalCount && result[0].TotalCount > 0) {
        return result[0].TotalCount;
    } else {
        return 0;
    }
}

exports.search = async (offset, pageSize, key) => {
    const query = `SELECT  iiii.LoggedIP as ID_Value, t.* FROM aiimma_truck_maintenance_journey_booking_details t  join aiima_transporter_driver_bthb_booking iiii on t.bookingid = iiii.ID  WHERE  LOWER(t.bookingid) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.maintenanceDescription) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.RecordAddedBy) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.LoggedIP) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.RecordCreatedAt) LIKE `+SqlString.escape('%'+key+'%')+` LIMIT ?, ?`;
    return getRows(query,[offset, pageSize]);
}

exports.searchCount = async (key) => {
    const query = `SELECT count(*) TotalCount FROM aiimma_truck_maintenance_journey_booking_details t  join aiima_transporter_driver_bthb_booking iiii on t.bookingid = iiii.ID  WHERE  LOWER(t.bookingid) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.maintenanceDescription) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.RecordAddedBy) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.LoggedIP) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.RecordCreatedAt) LIKE `+SqlString.escape('%'+key+'%')+` `;
    const result = await getRows(query);
    if (result && result[0] && result[0].TotalCount && result[0].TotalCount > 0) {
        return result[0].TotalCount;
    } else {
        return 0;
    }
}


exports.getByID = async (offset, pageSize, ID) => {
    const query = `SELECT  iiii.LoggedIP as ID_Value, t.* FROM aiimma_truck_maintenance_journey_booking_details t  join aiima_transporter_driver_bthb_booking iiii on t.bookingid = iiii.ID  WHERE t.ID= ? LIMIT ?, ?`;
    return getRows(query,[ID,offset,pageSize]);
}

exports.getByIDCount = async (key) => {
    const query = `SELECT count(*) TotalCount FROM aiimma_truck_maintenance_journey_booking_details t  join aiima_transporter_driver_bthb_booking iiii on t.bookingid = iiii.ID  WHERE t.ID= ?`;
    const result = await getRows(query,[ID,offset,pageSize]);
    if (result && result[0] && result[0].TotalCount && result[0].TotalCount > 0) {
        return result[0].TotalCount;
    } else {
        return 0;
    }
}
