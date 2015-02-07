/**    node加解密模块 */
var crypto = require('crypto');
/**    underscore */
var _ = require('underscore');
/**    zlib */
var zlib = require('zlib');
var gzip = zlib.Gzip;
/**    promise Q modules */
var Q = require('q');

/**
 * 自定义二进制加解密处理通用类
 *
 * 基于Feistel结构进行重写
 * 参考文章：http://www.jiamisoft.com/blog/index.php/5448-zhihuanyiweidanzijiefenzujiami.html
 *
 * base64(gzip(binary))
 *
 */
module.exports = {

    /**加密key来源*/
    keySource : [
        '1','2','3','4','5','6','7','8','9',
        'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
        'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
        '!','@','#','$','%','^','&','*','(',')','-','=','+'
    ],
    /**加密keyBuffer对象*/
    keyBuffer : null,
    /**
     * 二进制加密
     * @param plainData             待加密原始数据   String
     * @return {promise}
     */
    cipherBinary : function(plainData){

        //如传入空待加密字符串则返回空
        if(!plainData)
            return '';
        //初始化加密key
        this.initKey();
        //将待加密数据装换为Buffer类型
        var sourceBuffer = new Buffer(plainData);
        //console.log(sourceBuffer.length);
        //进行第一轮加密，秘钥需要进行异或时秘钥需要进行按位取反
        for (var i = 0; i < sourceBuffer.length; i++) {
            var bit = sourceBuffer.readInt8(i);//读取8bit进行处理
            //交换位置
            var first =  this.changePosNumberToBit(bit);
            var firstNum = this.bitToNumber(first);//将交换后的二进制转换为number

            //对变换后的数据进行异或
            var xor = firstNum ^ (~this.keyBuffer.readInt8(0));//第一轮将key取反在进行异或操作。

            //写入新的sourceBuffer内
            sourceBuffer.writeInt8(xor, i);
        }
        //console.log('---'+(~this.keyBuffer.readInt8(0)));
        //第二轮加密 每8个字节交换；第三轮加密 从第一个8bit后四位与第二个8bit前四位交换后与key异或
        var bufferLen =  sourceBuffer.length;
        bufferLen = ((bufferLen%2 ==0) ? bufferLen : (bufferLen-1));//注意此步骤如果是奇数个将会舍弃最后8bit
        for (var i = 0; i < bufferLen; i=i+2) {
            var aLeft = sourceBuffer.readInt8(i);
            var bRight = sourceBuffer.readInt8(i+1);

            //交换left和right
            aLeft = aLeft ^ bRight;
            bRight = aLeft ^ bRight;
            aLeft = aLeft ^ bRight;

            //从第一个8bit后四位与第二个8bit前四位交换后与key异或
            var aLeft4Bit = this.getLeftFourBit(aLeft);
            var aRight4Bit = this.getRightFourBit(aLeft);

            var bLeft4Bit = this.getLeftFourBit(bRight);
            var bRight4Bit = this.getRightFourBit(bRight);

            //aLeft的后4位和bRight前四位调换位置
            aLeft = this.bitToNumber(aLeft4Bit+bLeft4Bit);
            bRight = this.bitToNumber(aRight4Bit+bRight4Bit);

            //对新的a和b进行异或运算写入buffer
            var aXor = aLeft ^ (~this.keyBuffer.readInt8(0));//注意此步骤如果是奇数个将会舍弃最后8bit
            var bXor = bRight ^ (~this.keyBuffer.readInt8(0));//注意此步骤如果是奇数个将会舍弃最后8bit

            sourceBuffer.writeInt8(aXor, i);
            sourceBuffer.writeInt8(bXor, i+1);
        }

        //第四轮交换 折半整体换位，如果不是偶数个则最后一位放到第一位
        var tempBuffer = new Buffer(sourceBuffer.length);
        var half = bufferLen/2;
        var leftBuffer = sourceBuffer.slice(0,half);
        var rightBuffer = sourceBuffer.slice(half,bufferLen);

        //非偶数个最后一位放在现在数据的地址为  //补上最后一个8bit
        if(sourceBuffer.length%2 !=0){
            var lastBuffer = sourceBuffer.readInt8(sourceBuffer.length-1);
            //开始填充数据
            tempBuffer.writeInt8(lastBuffer, 0);//将最后一个放在第一位
            rightBuffer.copy(tempBuffer,1,0,half);
            leftBuffer.copy(tempBuffer,half+1,0,half);
        }else{
            rightBuffer.copy(tempBuffer,0,0,half);
            leftBuffer.copy(tempBuffer,half,0,half);
        }
        //console.log(sourceBuffer);
        sourceBuffer = tempBuffer;
        tempBuffer = null;


        //第五步将秘钥源码存在buffer第八位，不足第八位时将放在buffer末尾
        tempBuffer = new Buffer(sourceBuffer.length+1);
        var len = sourceBuffer.length;
        if(len < 8){//将秘钥放在末尾
            sourceBuffer.copy(tempBuffer,0,0,tempBuffer.length);
            this.keyBuffer.copy(tempBuffer,sourceBuffer.length,0,1);
        }else{
            sourceBuffer.copy(tempBuffer,0,0,7);
            this.keyBuffer.copy(tempBuffer,7,0,1);
            sourceBuffer.copy(tempBuffer,8,7,sourceBuffer.length);
        }

        sourceBuffer = tempBuffer;
        tempBuffer = null;

        //第六步对数据进行gzip压缩
        var _self = this;
        var deferred = Q.defer();
        var gzip = Q.nfbind(zlib.gzip);
        gzip(sourceBuffer)
            .catch(function(reason){
                deferred.reject(reason);
            })
            .done(function(cipherData){
                deferred.resolve(_self.cipherBase64(cipherData));
            }
        );
        /**
         zlib.gzip(sourceBuffer, function(err, data){
            if(err)
                callback(err);

            callback(null, _self.cipherBase64(data));
        });
         */
        return deferred.promise;
    },
    /**
     * 二进制解密
     * @param  decipherData            待解密字符串 String
     * @return {String}
     */
    decipherBinary : function(decipherData){
        var _self = this;
        var deferred = Q.defer();

        //gzip解密数据
        var gunzip = Q.nfbind(zlib.gunzip);
        gunzip(_self.decipherBase64(decipherData))
            .catch(function(reason){
                deferred.reject(reason);
            })
            .done(function(decBuffer){
                //从base64解密解压后的数据中提取中秘钥key
                var key = 0;
                var len= decBuffer.length;
                var temp = new Buffer(len-1);
                if(len< 8){//将秘钥放在末尾
                    decBuffer.copy(temp,0,0,decBuffer.length-1);
                    key = decBuffer.readInt8(decBuffer.length-1);
                }else{
                    decBuffer.copy(temp,0,0,7);
                    decBuffer.copy(temp,7,8,decBuffer.length);
                    key = decBuffer.readInt8(7);
                }
                //console.log('从待解密串中获取的key ：'+key);
                decBuffer = temp;
                temp = null;


                //第一轮解密，折半整体换位，如果不是偶数个则第一位放到最后一位
                len = decBuffer.length;
                len = ((len%2 ==0) ? len : (len-1));
                half = len/2;

                temp = new Buffer(decBuffer.length);
                if(decBuffer.length%2 !=0){//补上最后一个8bit
                    var firstBuffer = decBuffer.readInt8(0);
                    var leftBuffer = decBuffer.slice(1,half+1);
                    var rightBuffer = decBuffer.slice(half+1,decBuffer.length);
                    //开始填充数据
                    rightBuffer.copy(temp,0,0,half);
                    leftBuffer.copy(temp,half,0,half);

                    temp.writeInt8(firstBuffer, temp.length-1);//将最后一个放在第一位
                }else{
                    var leftBuffer = decBuffer.slice(0,half);
                    var rightBuffer = decBuffer.slice(half,len);

                    rightBuffer.copy(temp,0,0,half);
                    leftBuffer.copy(temp,half,0,half);
                }
                decBuffer = temp;
                temp = null;
                //console.log(decBuffer);
                //第二轮及第三轮解密
                for (var i = 0; i < len; i=i+2) {
                    var a = decBuffer.readInt8(i);
                    var b = decBuffer.readInt8(i+1);
                    //console.log(a);
                    a = a ^ (~key);
                    b = b ^ (~key);

                    //a = a ^ key;
                    //b = b ^ key;

                    //获取a,b的前4bit和后4bit
                    var aLeft = _self.getLeftFourBit(a);
                    var aRight = _self.getRightFourBit(a);

                    var bLeft = _self.getLeftFourBit(b);
                    var bRight = _self.getRightFourBit(b);

                    //a的后4位和b前四位调换位置
                    a = _self.bitToNumber(aLeft+bLeft);
                    b = _self.bitToNumber(aRight+bRight);

                    a = a ^ b;
                    b = a ^ b;
                    a = a ^ b;

                    decBuffer.writeInt8(a, i);
                    decBuffer.writeInt8(b, i+1);
                }
                //第四轮解密
                for (var i = 0; i < decBuffer.length; i++) {
                    var bit = decBuffer.readInt8(i);
                    //异或
                    var xor = bit ^ (~key);
                    //var xor = bit ^ key;
                    //调换前后4位位置
                    var first =  _self.changePosNumberToBit(xor);
                    var firstNum = _self.bitToNumber(first);
                    decBuffer.writeInt8(firstNum, i);
                }

                deferred.resolve(decBuffer.toString());
            });
        return deferred.promise;
    },
    /**
     * 从key资源列表中获得本次key
     * @return {Buffer}
     */
    initKey : function(){
        var random = _.random(0, 73);
        var keySource = this.keySource[random];
        //console.log('key ：'+random);
        //console.log('key 原始数据 ：'+keySource);
        this.keyBuffer = new Buffer(keySource);
        //this.keyBuffer = new Buffer('x');
    },
    /**
     * base64加密
     * @param plainBuffer           需要加密的数据 Buffer
     * @return String               utf8编码
     */
    cipherBase64 : function(plainBuffer){
        //var buffer = new Buffer(plainData, 'utf8');
        return plainBuffer.toString('base64');
    },
    /**
     * base64解密
     * @param cipherData            需要解密的数据 String
     * @return Buffer               utf8编码
     */
    decipherBase64 : function(cipherData){
        return new Buffer(cipherData, 'base64');
    },
    /**
     * 二进制转换为十进制
     * @param bitString     string
     * @returns {*}
     */
    bitToNumber : function(bitString){
        if(!bitString){
            return 0;
        }
        /***/
        var len = bitString.length;
        var result;
        if(len != 4 && len != 8){
            return 0;
        }
        //8 bit处理此处理方式是为了保证不超出buffer范围
        if(len == 8) {
            if (bitString.charAt(0) == '0') {//正数
                result = parseInt(bitString, 2);
            } else {//负数
                result = parseInt(bitString, 2) - 256;
            }
        }else{//4 bit处理
            result = parseInt(bitString, 2);
        }
        return result;
        //return  parseInt(bitString, 2);//直接转换为10进制
    },
    /**
     * 转换为二进制格式
     * @param number         int
     * @returns {string}
     */
    numberToBit : function(number){
        return ''
            +((number >> 7) & 0x1)
            +((number >> 6) & 0x1)
            +((number >> 5) & 0x1)
            +((number >> 4) & 0x1)
            +((number >> 3) & 0x1)
            +((number >> 2) & 0x1)
            +((number >> 1) & 0x1)
            +((number >> 0) & 0x1);
    },
    /**
     * 获得指定的左4bit
     * @param number         int
     * @returns {string}
     */
    getLeftFourBit : function(number){
        return ''
            +((number >> 7) & 0x1)
            +((number >> 6) & 0x1)
            +((number >> 5) & 0x1)
            +((number >> 4) & 0x1);
    },
    /**
     * 获得指定的右4bit
     * @param number
     * @returns {string}
     */
    getRightFourBit : function(number){
        return ''
            +((number >> 3) & 0x1)
            +((number >> 2) & 0x1)
            +((number >> 1) & 0x1)
            +((number >> 0) & 0x1);
    },
    /**
     * 转换为二进制格式（左四位和右四位变换位置）
     * 例： 00110010 变换后 00100011
     * @param number          int
     * @returns {string}
     */
    changePosNumberToBit : function(number){
        return ''
            +((number >> 3) & 0x1)
            +((number >> 2) & 0x1)
            +((number >> 1) & 0x1)
            +((number >> 0) & 0x1)
            +((number >> 7) & 0x1)
            +((number >> 6) & 0x1)
            +((number >> 5) & 0x1)
            +((number >> 4) & 0x1);
    }
}
