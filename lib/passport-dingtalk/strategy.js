/**
 * Created by along on 16/3/12.
 */
/**
 * Module dependencies.
 */
var util = require('util')
    , querystring= require('querystring')
    , OAuth2Strategy = require('passport-oauth').OAuth2Strategy
    , InternalOAuthError = require('passport-oauth').InternalOAuthError;

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

    var _self = this;

    // extra url
    this._persistentCodeUrl = "https://oapi.dingtalk.com/sns/get_persistent_code";
    this._snsTokenUrl = "https://oapi.dingtalk.com/sns/get_sns_token";
    this._persistentCodeMemStore = {}
    this._persistentCodeGet = options.PersistentCodeGet || function(openid,callback) {
        callback(null, _self._persistentCodeMemStore[openid]);
    }

    OAuth2Strategy.call(this, options, verify);

    this._preloadToken(options.clientID,options.clientSecret,function(err,access_token) {
        if (err) {
            console.log("fail to get access_token");
            return;
        }

        _self.access_token = access_token;

        _self.name = 'dingtalk';

        _self._oauth2.getAuthorizeUrl = function(params) {
            var params= params || {};
            var options = {
                appid: _self._clientId,
                redirect_uri: params['redirect_uri'],
                response_type: params['response_type'],
                scope: params['scope'],
                state: params['state']
            }
            return _self._baseSite + _self._authorizeUrl + "?" + querystring.stringify(options)+'#ding_redirect';
        }

        _self._oauth2.getOAuthAccessToken = function(code, params, callback) {
            var params = params || {};
            params['tmp_auth_code'] = code;

            var post_data = querystring.stringify(params);
            var post_headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
            };

            _self._request("POST", _self._persistentCodeUrl() + "?access_token=" + _self.access_token , post_headers, post_data, null, function(error, data, response) {
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

                        _self._request("POST",_self._snsTokenUrl + "?access_token=" + _self.access_token, post_headers, post_data, null, function(error,data,response) {
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
                            }
                            callback(new Error(results['errmsg']));

                        });
                        
                    }

                    callback(new Error(results['errmsg']))
                    
                }
            });
        }

    });
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

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
