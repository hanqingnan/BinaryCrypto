/** 自定义加密模块 */
var bc = require('../index');

/** 待加密字符串 */
var source = {
    "xxxx1":"xxxxx1",
    "xxxx2":"xxxxx2"
};

source = {
    "hiu":"",
    "protocol":"0.0.2",
    "pw":"e10adc3949ba59abbe56e057f20f883e",
    "un":"13810708420",
    "mobile":{
        "model":"K-Touch Tou ch3",
        "height":854,
        "apn":"wifi",
        "platformId":"4.3",
        "idfa":"",
        "width":480
    },
    "version":"0.2.0"
};


/** */
bc.cipherBinary(JSON.stringify(source))
    .then(function(data){
        console.log(data);
        return bc.decipherBinary(data)
    })
    .done(function(data){
        console.log(data);
    });