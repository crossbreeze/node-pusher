module.exports = (function() {
  var crypto = require('crypto');
  var http = require('http');
  var https = require('https');

  var Pusher = function(options) {
    this.options = options;
    return this;
  }

  Pusher.prototype.domain = 'api.pusherapp.com';

  Pusher.prototype.auth = function(socketId, channel, channelData) {
    var returnHash = {}
    var channelDataStr = ''
    if (channelData) {
      channelData = JSON.stringify(channelData);
      channelDataStr = ':' + channelData;
      returnHash['channel_data'] = channelData;
    }
    var stringToSign = socketId + ':' + channel + channelDataStr;
    returnHash['auth'] = this.options.key + ':' + crypto.createHmac('sha256', this.options.secret).update(stringToSign).digest('hex');
    return(returnHash);
  }

  Pusher.prototype.trigger = function(channel, event, message, socketId, callback) {
    if (typeof callback === 'undefined') {
      callback = socketId;
      socketId = '';
    }
    var timestamp = parseInt(new Date().getTime() / 1000);
    var requestBody = JSON.stringify(message);
    var hash = crypto.createHash('md5').update(new Buffer(requestBody).toString('binary')).digest('hex');

    var params = [
      'auth_key=', this.options.key,
      '&auth_timestamp=', timestamp,
      '&auth_version=', '1.0',
      '&body_md5=', hash,
      '&name=', event
    ];
    if (socketId) {
      params.push('&socket_id=', socketId);
    }
    var queryString = params.join('');

    var path = '/apps/' + this.options.appId + '/channels/' + channel + '/events';
    var signData = ['POST', path, queryString].join('\n');
    var signature = crypto.createHmac('sha256', this.options.secret).update(signData).digest('hex');

    path = path + '?' + queryString + '&auth_signature=' + signature;

    var domain;
    if (this.options.host) {
      domain = this.options.host
    } else {
      domain = this.domain
    }
    var port;
    if (this.options.port) {
      port = this.options.port
    } else {
      port = this.options.ssl ? 443 : 80;
    }
    
    var options = {
      'method': 'POST', 
      'path': path,
      'host': domain,
      'port': port,
      'headers': {
        'content-type': 'application/json',
        'content-length': new Buffer(requestBody).toString('binary').length
      }
    }
 
    var request;
    if (this.options.ssl) {
      // Verify server certificate with our CAs
      options['rejectUnauthorized'] = true
      options.agent = new https.Agent(options);
      request = https.request(options);
    } else {
      request = http.request(options);
    }

    if(callback) {
      var response = '';
      request.on('data', function(data) {
        response += data;
        if (response.length > 1e4) {
          // No slanger server will ever reply more than a short line of text
          request.connection.destroy();
        }
      });
      request.on('end', function() {
        callback(null, request, response);
      });
      request.on('error', function(error) {
        callback(error, request, null);
      });
    }

    request.write(requestBody);
    request.end();

    return this;
  }

  return Pusher;
})();
