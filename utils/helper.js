const PAGE_SIZE = 20;
const PAGE_NO = 1;
var crypto = require('crypto');
exports.getPageNo = async (req) => {
    let pageNo = PAGE_NO;
    if (req.query && req.query.pageNo) {
        pageNo = parseInt(req.query.pageNo);
    }
    return pageNo;
}

exports.getPageSize = async (req) => {
    let pageSize = PAGE_SIZE;
    if (req.query && req.query.pageSize) {
        pageSize = parseInt(req.query.pageSize);
    }
    return pageSize;
}

exports.encrypt = (text) => {
    var cipher = crypto.createCipheriv('aes-256-gcm', process.env.SECRET_KEY);
    var crypted = cipher.update(text, 'utf8', 'hex');
    crypted += cipher.final('hex');
    return crypted;
};

exports.decrypt = (text) => {
    var decipher = crypto.createDecipheriv('aes-256-gcm', process.env.SECRET_KEY);
    var dec = decipher.update(text, 'hex', 'utf8');
    dec += decipher.final('utf8');
    return dec;
};

exports.extractToken = (req) => {
    if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
        return req.headers.authorization.split(' ')[1];
    } else if (req.query && req.query.token) {
        return req.query.token;
    }
    return null;
}
