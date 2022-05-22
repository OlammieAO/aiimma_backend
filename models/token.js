const {getRows} = require('../database/query');
/* const connection = require('./connection');
const bcrypt = require('bcrypt');
const session = require('express-session');
const dbhelper = require("./models/db_helper.js");
const joi = require("joi");
 */
const userdetails = {};

//const saltRound = 10;

exports.authLogin = async (username,password) => {
    const query = `SELECT  t.* FROM aiimma_membersaccess t  WHERE t.EmailID='${username}' AND t.Pwd='${password}' LIMIT 0,1`;

    //const query = 
    //connection.query

return getRows(query); 
} 

/* exports.authLogin = async (req,res) => {
    connection.query("SELECT * FROM aiimma_membersaccess WHERE username = ? AND LoginStatus='Enabled'", username, (err, result) => {
        if(err){
        return res.send({err: err});
      }
      
         if(result.length > 0) {
         bcrypt.compare(password, result[0].Pwd, (error, response) => {
          if(response) {
       
        return result;
      } // closes this if
          else {
         return res.json({
      auth: false,
      message: "Wrong login credentials supplied."
      });
      } // closes this else
      }); // closes bcrypt compare function
      } // closes result if
      
         else {
         return res.send({
      auth: false,
      message: "User doesn't exist."
      });
      } // closes else for the result if
      
      }); // closes db.query function
      
};
 */
