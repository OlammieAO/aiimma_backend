//const dotenv = require('dotenv')
const express = require("express");
const router = express.Router();


const connection = require('../database/connection');

//const connectionn = require('../database/connection');

const bcrypt = require('bcrypt');


const driverLoginVW = (loginID) =>{
    const sqlSelect = "SELECT * FROM DriverDetailsForState_VW WHERE Email='" + loginID + "' OR Phone='" + loginID + "' LIMIT 1";
    connection.query(sqlSelect, (err, result)=> {
          if(!err)        
          {
              return result;
          }           
    });
}

const agentLoginVW = (loginID) =>{
    const sqlSelect = "SELECT * FROM AgentDetailsForState_VW WHERE Email=? OR Phone=? LIMIT 1";
    connection.query(sqlSelect, loginID, (err, result)=> {
          if(!err)        
          {
              return result;
          }           
    });
}

const transporterLoginVW = (loginID) =>{
    const sqlSelect = "SELECT * FROM TranspoterDetailsForState_VW WHERE Email=? OR Phone=? LIMIT 1";
    connection.query(sqlSelect, loginID, (err, result)=> {
          if(!err)        
          {
              return result;
          }           
    });
}

const hbbtLoginVW = (loginID) =>{
    //const sqlSelect = "SELECT * FROM HBBTDetailsForState_VW WHERE Email='" + loginID + "' OR Phone='" + loginID + "' LIMIT 1";
    
    const sqlSelect = "SELECT * FROM HBBTDetailsForState_VW WHERE Email=? OR Phone=? LIMIT 1"
    connection.query(sqlSelect, loginID, (err, result)=> {
          if(!err)        
          {
              return result;
          }           
    });
}

const adminStaffLoginVW = (loginID) =>{
    const sqlSelect = "SELECT * FROM AdminStaffDetailsForState_VW WHERE Email=? OR Phone=? LIMIT 1";
    connection.query(sqlSelect, loginID, (err, result)=> {
          if(!err)        
          {
              return result;
          }           
    });
}

const updateEmailVerification = (token) =>{
        
    const sqlSelect = "UPDATE aiimma_membersaccess SET emailValidated='1' WHERE emailActivationCode =? LIMIT 1";

    connection.query(sqlSelect, token, (err, result)=> {
          if(result)        
          {
              return true;
          } 
          
          else{
              return false;
          }
    });
}

const transporterWalletBalance = (login_id, registeras) =>{
        
    const sqlSelect = "SELECT AccountBalance, FirstTimeBalance aiimma_customers_deposit_balance WHERE customer_id =? AND customer_role=? LIMIT 1";

    connection.query(sqlSelect, token, (err, result)=> {
          if(result)        
          {
              return result;
          } 
          
          else{
              return err;
          }
    });
}

module.exports = { driverLoginVW, agentLoginVW, transporterLoginVW, hbbtLoginVW, updateEmailVerification, adminStaffLoginVW };