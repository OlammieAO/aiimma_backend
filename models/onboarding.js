const {getRows} = require('../database/query');

const connection = require('./connection');

exports.authLogin = async (username,password) => {
    const query = `SELECT  t.* FROM aiimma_membersaccess t  WHERE t.EmailID='${username}' AND t.Pwd='${password}' LIMIT 0,1`;

    

return getRows(query); 
}

