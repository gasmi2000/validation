var exec = require('cordova/exec');

exports.coolMethod = function (arg0, success, error) {
    exec(success, error, 'Validation', 'coolMethod', [arg0]);
};


exports.validatePassword = function (arg0, success, error) {
    exec(success, error, 'Validation', 'validatePassword', [arg0]);
};
