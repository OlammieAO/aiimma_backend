//require('dotenv').config({ debug: true, override: false });
const {v4: uuid} = require('uuid');
const express = require('express');
const jwt = require("jsonwebtoken");
const bcrypt = require('bcrypt');
const crypto = require('crypto');

const userid = () =>{
    return uuid();   
    };

const getRandomNumberBetween = (min,max) => {
        return Math.floor(Math.random()*(max-min+1)+min);        
    }

const generateToken = () => {
    var token = null;
    crypto.randomBytes(28, function(err, buffer) {
        token = buffer.toString('hex');          
      });

      return token;
}    

const emailActivation = (userid) =>{   
    var finalToken = generateToken() + userid + generateToken();
          
      return finalToken;
}    

module.exports = { userid, getRandomNumberBetween, emailActivation, generateToken };    