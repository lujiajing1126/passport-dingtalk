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

    OAuth2Strategy.call(this, options, verify);
    this.name = 'dingtalk';

    this._oauth2.getAuthorizeUrl= function(params) {
        var params= params || {};
        //params['appid'] = this._clientId;
        var options={
            appid:this._clientId,
            redirect_uri:params['redirect_uri'],
            response_type:params['response_type'],
            scope:params['scope'],
            state:params['state']
        }
        return this._baseSite + this._authorizeUrl + "?" + querystring.stringify(options)+'#ding_redirect';
    }

    this._oauth2.getOAuthAccessToken= function(code, params, callback) {
        var params= params || {};
        params['corpid'] = this._clientId;
        params['corpsecret'] = this._clientSecret;
        var codeParam = (params.grant_type === 'refresh_token') ? 'refresh_token' : 'code';
        params[codeParam]= code;

        var post_data= querystring.stringify(params);
        var post_headers= {
            'Content-Type': 'application/x-www-form-urlencoded'
        };

        this._request("GET", this._getAccessTokenUrl()+"?"+post_data, post_headers, null, null, function(error, data, response) {
            if( error )  callback(error);
            else {
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
                    results= querystring.parse( data );
                }
                var access_token= results["access_token"];
                var refresh_token= results["refresh_token"];
                delete results["refresh_token"];
                callback(null, access_token, refresh_token, results); // callback results =-=
            }
        });
    }
}


/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);


OAuth2Strategy.prototype._loadUserProfile = function(accessToken,done,params) {
    this.userProfile(accessToken,done,params)
};

/**
 * Retrieve user profile from Baidu.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `Baidu`
 *   - `id`               baidu userid
 *   - `nickname`         baidu username
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(accessToken,done,params) {
    var _self = this;
    this._oauth2.get('https://oapi.dingtalk.com/user/getuserinfo?code=' + params.code, accessToken, function (err, body, res) {
        try {
            var json = JSON.parse(body);
            _self.userProfileInfo(accessToken, json, done)
        } catch (e) {
            done(e);
        }
    });
}

Strategy.prototype.userProfileInfo = function(accessToken,profile,done) {
    this._oauth2.get('https://oapi.dingtalk.com/user/get?access_token=' + accessToken + '&userid=' + profile.userid, null, function (err, body, res) {
        try {
            var json = JSON.parse(body);
            done(null, {
                provider: 'dingtalk',
                id: json.openId,
                name: json.name,
                privateId: json.userid,
                mobile: json.mobile,
                email: json.email,
                headurl: json.avatar,
                deviceId: json.deviceId,
                _raw: body,
                _json: json
            }  );
        } catch (e) {
            done(e);
        }
    });
}


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
