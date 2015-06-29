var crypto = require('crypto-browserify');
var constants = require('constants');

var XECrypto = {};

XECrypto.rsaEncrypt = function(pubKey, text) {
    var pubKeyObj = {
        'key': pubKey,
        'padding': constants.RSA_PKCS1_PADDING
    }
    var encryptData = crypto.publicEncrypt(pubKeyObj, new Buffer(text));
    return encryptData.toString('base64');
}
XECrypto.rsaDecrypt = function(privateKey, text) {
    var privateKeyObj = {
        'key': privateKey,
        'padding': constants.RSA_PKCS1_PADDING
    }
    var decryptData = crypto.privateDecrypt(privateKeyObj, new Buffer(text, 'base64'));
    return decryptData.toString();
}

XECrypto.desEncrypt = function(key, iv, text) {
    var cipher = crypto.createCipheriv('des-cbc', new Buffer(key), new Buffer(iv));
    cipher.setAutoPadding(true);
    var result = [cipher.update(text, 'utf8')];
    result.push(cipher.final());

    return Buffer.concat(result).toString('base64');
}

XECrypto.desDecrypt = function(key, iv, text) {
    var decipher = crypto.createDecipheriv('des-cbc', new Buffer(key), new Buffer(iv));
    decipher.setAutoPadding(true);
    var result = [decipher.update(text, 'base64')];
    result.push(decipher.final());
    return Buffer.concat(result).toString('utf8');
}
