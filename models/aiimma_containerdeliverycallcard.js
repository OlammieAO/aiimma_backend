const {getRows, insertRow, updateRow, deleteRow} = require('../database/query');
var SqlString = require('sqlstring');

exports.find = async (offset, pageSize) => {
    const query = `SELECT  b.* FROM bookingvw b  LIMIT ?, ?`;
    return getRows(query,[offset,pageSize]);
}

exports.findById = async (ID) => {
    const query = `SELECT  b.* FROM bookingvw b WHERE t.ID=? LIMIT 0,1`;
    return getRows(query,[ID]);
}

//can't insert this
exports.insert = async (object) => {
    const query = `INSERT INTO aiima_transporter_driver_bthb_booking set ?`;
    const id = await insertRow(query, object);
    return id > 0 ;
}

//can update
exports.update = async (ID, object) => {
    const updateKeys = [];
    let updateValues = [];
    for (const key in object) {
        updateKeys.push(`${key}=?`);
        updateValues.push(`${object[key]}`);
    }
    let query = `UPDATE aiima_transporter_driver_bthb_booking SET ? WHERE ID= ?`;
    updateValues = updateValues.concat([ID])
    query = query.replace("?", updateKeys.join(","));
    const result = await updateRow(query, updateValues);
    return result ? this.findById(ID) : null;
}

//can remoce / delete
exports.remove = async (ID) => {
    const query = `DELETE FROM aiima_transporter_driver_bthb_booking Where ID= ? `;
    return deleteRow(query,[ID]);
}


exports.count = async () => {
    const query = `SELECT count(*) bookingvw FROM bookingvw b`;
    const result = await getRows(query);
    if (result && result[0] && result[0].TotalCount && result[0].TotalCount > 0) {
        return result[0].TotalCount;
    } else {
        return 0;
    }
}

exports.search = async (offset, pageSize, key) => {
    const query = `SELECT  SELECT  t.* FROM bookingvw t  WHERE  LOWER(t.BookingCode) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.JourneyCode) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.CompanyName) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Tran_FullName) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Dri_FullName) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.TruckPlateNumber) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.TruckName) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.BookingDate) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Container_MTU_No) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Container_Size) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Journey_Destination_Port) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.BookingStatus) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.TruckSize) LIKE `+SqlString.escape('%'+key+'%')+` LIMIT ?, ?`;
    return getRows(query,[offset, pageSize]);
}

exports.searchCount = async (key) => {

    const query = `SELECT  count(*) TotalCount FROM bookingvw t  WHERE  LOWER(t.BookingCode) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.JourneyCode) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.CompanyName) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Tran_FullName) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Dri_FullName) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.TruckPlateNumber) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.TruckName) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.BookingDate) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Container_MTU_No) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Container_Size) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.Journey_Destination_Port) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.BookingStatus) LIKE `+SqlString.escape('%'+key+'%')+` OR LOWER(t.TruckSize) LIKE `+SqlString.escape('%'+key+'%')+` `;

    
    const result = await getRows(query);
    if (result && result[0] && result[0].TotalCount && result[0].TotalCount > 0) {
        return result[0].TotalCount;
    } else {
        return 0;
    }
}


exports.getByID = async (offset, pageSize, ID) => {
    const query = `SELECT  bbb.UserID as ID_Value, nnn.CustomerID as ID_Value, yyy.LoggedIP as ID_Value, t.* FROM aiima_transporter_driver_bthb_booking t  join aiimma_transporters bbb on t.Transporter_id = bbb.ID  join aiimma_bt_hb_customers nnn on t.bt_hb_customer_id = nnn.ID  join aiimma_trucks yyy on t.Truck_id = yyy.ID  WHERE t.ID= ? LIMIT ?, ?`;
    return getRows(query,[ID,offset,pageSize]);
}

exports.getByIDCount = async (key) => {
    const query = `SELECT count(*) TotalCount FROM aiima_transporter_driver_bthb_booking t  join aiimma_transporters bbb on t.Transporter_id = bbb.ID  join aiimma_bt_hb_customers nnn on t.bt_hb_customer_id = nnn.ID  join aiimma_trucks yyy on t.Truck_id = yyy.ID  WHERE t.ID= ?`;
    const result = await getRows(query,[ID,offset,pageSize]);
    if (result && result[0] && result[0].TotalCount && result[0].TotalCount > 0) {
        return result[0].TotalCount;
    } else {
        return 0;
    }
}
exports.getByID = async (offset, pageSize, ID) => {
    const query = `SELECT  bbb.UserID as ID_Value, nnn.CustomerID as ID_Value, yyy.LoggedIP as ID_Value, t.* FROM aiima_transporter_driver_bthb_booking t  join aiimma_transporters bbb on t.Transporter_id = bbb.ID  join aiimma_bt_hb_customers nnn on t.bt_hb_customer_id = nnn.ID  join aiimma_trucks yyy on t.Truck_id = yyy.ID  WHERE t.ID= ? LIMIT ?, ?`;
    return getRows(query,[ID,offset,pageSize]);
}

exports.getByIDCount = async (key) => {
    const query = `SELECT count(*) TotalCount FROM aiima_transporter_driver_bthb_booking t  join aiimma_transporters bbb on t.Transporter_id = bbb.ID  join aiimma_bt_hb_customers nnn on t.bt_hb_customer_id = nnn.ID  join aiimma_trucks yyy on t.Truck_id = yyy.ID  WHERE t.ID= ?`;
    const result = await getRows(query,[ID,offset,pageSize]);
    if (result && result[0] && result[0].TotalCount && result[0].TotalCount > 0) {
        return result[0].TotalCount;
    } else {
        return 0;
    }
}
exports.getByID = async (offset, pageSize, ID) => {
    const query = `SELECT  bbb.UserID as ID_Value, nnn.CustomerID as ID_Value, yyy.LoggedIP as ID_Value, t.* FROM aiima_transporter_driver_bthb_booking t  join aiimma_transporters bbb on t.Transporter_id = bbb.ID  join aiimma_bt_hb_customers nnn on t.bt_hb_customer_id = nnn.ID  join aiimma_trucks yyy on t.Truck_id = yyy.ID  WHERE t.ID= ? LIMIT ?, ?`;
    return getRows(query,[ID,offset,pageSize]);
}

exports.getByIDCount = async (key) => {
    const query = `SELECT count(*) TotalCount FROM aiima_transporter_driver_bthb_booking t  join aiimma_transporters bbb on t.Transporter_id = bbb.ID  join aiimma_bt_hb_customers nnn on t.bt_hb_customer_id = nnn.ID  join aiimma_trucks yyy on t.Truck_id = yyy.ID  WHERE t.ID= ?`;
    const result = await getRows(query,[ID,offset,pageSize]);
    if (result && result[0] && result[0].TotalCount && result[0].TotalCount > 0) {
        return result[0].TotalCount;
    } else {
        return 0;
    }
}
