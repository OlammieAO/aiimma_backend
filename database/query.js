const connection = require('./connection');

exports.getRows = async (query,param) => {
    return connection.query(query,param);
}

exports.insertRow = async (query, param) => {
    const result = await connection.query(query, param);
    if (result && result.affectedRows > 0) {
        return result.insertId;
    } else {
        return 0;
    }
}

exports.updateRow = async (query, valueArray) => {
    const result = await connection.query(query, valueArray);
    return !!(result && result.affectedRows > 0);
}

exports.deleteRow = async (query,param) => {
    const result = await connection.query(query,param);
    return !!(result && result.affectedRows > 0);
}
