/**
 * Created by along on 16/3/12.
 */
/**
 * Module dependencies.
 */
var util = require('util')
    , querystring= require('querystring')
    , OAuth2Strategy = require('passport-oauth').OAuth2Strategy
    , InternalOAuthError = require('passport-oauth').InternalOAuthError
    , Promise = require('bluebird');

/*
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
    options = options || {};
    options.authorizationURL = options.authorizationURL || 'https://oapi.dingtalk.com/connect/oauth2/authorize';
    options.tokenURL = options.tokenURL || 'https://oapi.dingtalk.com/gettoken';
    options.scopeSeparator = options.scopeSeparator || ',';

    var that = this;
    // extra url
    this._persistentCodeUrl = "https://oapi.dingtalk.com/sns/get_persistent_code";
    this._snsTokenUrl = "https://oapi.dingtalk.com/sns/get_sns_token";
    this._persistentCodeMemStore = {};
    this._persistentCodeGet = options.PersistentCodeGet || function(openid,callback) {
        callback(null, that._persistentCodeMemStore[openid]);
    }

    OAuth2Strategy.call(this, options, verify);

    this.name = 'dingtalk';

    setInterval(function() {
        var preloadToken = Promise.promisify(that._preloadToken,{context:that})

        preloadToken(that._oauth2._clientId,that._oauth2._clientSecret).bind(that).then(function(access_token) {
            this.access_token = access_token;
        }).done()
    },1000 * 3600 * 1.5)
}


/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);


OAuth2Strategy.prototype._loadUserProfile = function(accessToken,done,params) {
    this.userProfile(accessToken,done,params)
};

Strategy.prototype.userProfile = function(accessToken,done,params) {
    var _self = this;
    this._oauth2._request("GET",'https://oapi.dingtalk.com/sns/getuserinfo?sns_token=' + accessToken, null,null,null,function (err, body, res) {
        try {
            var json = JSON.parse(body);
            done(null,{
                provider: 'dingtalk',
                id: json.user_info.openid,
                unionid: json.user_info.unionid,
                dingId: json.user_info.dingId,
                name: json.user_info.nick,
                mobile: json.user_info.maskedMobile,
                corp: json.corp_info,
                _raw: body,
                _json: json
            })
        } catch (e) {
            done(e);
        }
    });
};

Strategy.prototype._preloadToken = function(clientId, clientSecret, callback) {
    var url = "https://oapi.dingtalk.com/sns/gettoken?appid=" + clientId + "&appsecret=" + clientSecret;
    this._oauth2._request("GET", url, null, null, null, function(err, body, res) {
        if (err) {
            return callback(err,null);
        }

        var json;
        try {
            json = JSON.parse(body);
        } catch(_) {
            return callback(new Error("parse body fail"),null);
        }

        if (json['errmsg'] === "ok" && json['errcode'] === 0) {
            return callback(null,json['access_token']);
        }

        return callback(new Error(json['errmsg']),null);
    })
}

Strategy.prototype.init = function(successCallback) {
    var preloadToken = Promise.promisify(this._preloadToken,{context:this})

    preloadToken(this._oauth2._clientId,this._oauth2._clientSecret).bind(this).then(function(access_token) {
        var self = this;

        this.access_token = access_token;

        this._oauth2.getOAuthAccessToken = function(code, params, callback) {
            var params = {
                'tmp_auth_code': code
            };

            var post_data = JSON.stringify(params);
            var post_headers = {
                'Content-Type': 'application/json',
            };

            this._request("POST", self._persistentCodeUrl + "?access_token=" + self.access_token , post_headers, post_data, null, function(error, data, response) {
                if( error ) {
                    callback(error);
                } else {
                    var results;
                    try {
                        // As of http://tools.ietf.org/html/draft-ietf-oauth-v2-07
                        // responses should be in JSON
                        results= JSON.parse( data );
                    }
                    catch(e) {
                        // .... However both Facebook + Github currently use rev05 of the spec
                        // and neither seem to specify a content-type correctly in their response headers :(
                        // clients of these services will suffer a *minor* performance cost of the exception
                        // being thrown
                        results = querystring.parse( data );
                    }
                    if (results['errcode'] === 0 && results['errmsg'] === 'ok') {
                        var persistent_code = results["persistent_code"];
                        var open_id = results["openid"];

                        var params = {
                            'openid': open_id,
                            'persistent_code': persistent_code
                        }

                        self._oauth2._request("POST",self._snsTokenUrl + "?access_token=" + self.access_token, post_headers, JSON.stringify(params), null, function(error,data,response) {
                            if( error ) {
                                callback(error);
                            } else {
                                var results;
                                try {
                                    // As of http://tools.ietf.org/html/draft-ietf-oauth-v2-07
                                    // responses should be in JSON
                                    results = JSON.parse( data );
                                }
                                catch(e) {
                                    // .... However both Facebook + Github currently use rev05 of the spec
                                    // and neither seem to specify a content-type correctly in their response headers :(
                                    // clients of these services will suffer a *minor* performance cost of the exception
                                    // being thrown
                                    results = querystring.parse( data );
                                }
                            }

                            if (results['errcode'] === 0 && results['errmsg'] === 'ok') {
                                var sns_token = results['sns_token'];
                                callback(null, sns_token, null, results); // callback results =-=
                            } else {
                                callback(new Error(results['errmsg']));
                            }
                        });
                    } else {
                        callback(new Error(results['errmsg']))
                    }
                    
                }
            });
        }
        if (successCallback) {
            successCallback(self)
        }

    }).catch(function(err){
        console.log(err)
    }).done();
}

Strategy.prototype.authorizationParams = function(options) {
  return {appid: this._oauth2._clientId};
}

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
