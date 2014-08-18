
/**
 * Module dependencies.
 */

var express = require('express');
var routes = require('./routes');
var user = require('./routes/user');
var http = require('http');
var https = require('https');
var path = require('path');
var passport = require('passport');
var RememberMeStrategy = require('passport-remember-me').Strategy;
var LocalStrategy = require('passport-local').Strategy;
var OAuth2Strategy = require('passport-oauth2').Strategy;
var util = require('util');
var fs = require('fs');
var flash = require('connect-flash');

var token_file = 'tokens.json';

function getTokens() {
  var tokens = {};

  if (fs.existsSync(token_file)) {
    var tokens_txt = fs.readFileSync(token_file, {encoding: 'utf8'});
    tokens = tokens_txt ? JSON.parse(tokens_txt) : {};
  }

  return tokens;
}

function saveTokens(tokens) {
  var tokens_txt = JSON.stringify(tokens);
  fs.writeFileSync(token_file, tokens_txt, {encoding: 'utf8'});
}

function saveToken(uid, callback) {
  token = parseInt(Math.random() * parseInt('FFFFFFFF', 16), 10).toString(16).toUpperCase();

  var tokens = getTokens();
  tokens[token] = uid;
  saveTokens(tokens);
  return callback(token);
}

function consumeToken(token, callback) {
  var tokens = getTokens();
  var uid = tokens[token];
  delete tokens[token];
  saveTokens(tokens);
  if (uid != null) {
    callback(uid);
  } else {
    console.log(util.format('No matching token: \'%s\'', token));
    callback(null);
  }
}

passport.use('local', new LocalStrategy(
  function(username, password, done) {
    return done(null, 1);
  }
));

passport.use('remember-me', new RememberMeStrategy(
  function(token, done) {
    consumeToken(token, function(uid) {
      console.log(util.format('Consume token \'%s\'', token));
      if (uid == null) {
        done(null, false);
      } else {
        done(null, uid);
      }
    });
  },
  function(user, done) {
    saveToken(user, function(token) {
      console.log(util.format('Strategy: Saving token \'%s\'', token));
      return done(null, token);
    });
  }
));

passport.use('oauth2', new OAuth2Strategy({
    authorizationURL: 'https://accounts.google.com/o/oauth2/auth',
    tokenURL: 'https://accounts.google.com/o/oauth2/token',
    clientID: '922391096653-1slbbcf5ujrrfn5oeap0a0acvmr626l7.apps.googleusercontent.com',
    clientSecret: 'e5Lfe_nTegO37xPjqLjaYXiD',
    callbackURL: "https://localhost:4000/oauth2callback",
    scope: "openid",
    state: "xyzzy"
  },
  function(accessToken, refreshToken, profile, done) {
    return done(null, 1);
  }
));

passport.serializeUser(function(user, done) {
  done(null, JSON.stringify(user));
});

passport.deserializeUser(function(user, done) {
  done(null, JSON.parse(user));
});

var app = express();

// all environments
app.set('port', process.env.PORT || 4000);
app.set('views', __dirname + '/views');
app.set('view engine', 'jade');
app.use(express.favicon());
app.use(express.logger('dev'));
app.use(express.bodyParser());
app.use(express.methodOverride());
app.use(express.cookieParser('Plover'));
app.use(express.session({secret: 'Plover', cookie: { maxAge: 30000 }}));
app.use(flash());
app.use(passport.initialize());
app.use(passport.session());
app.use(passport.authenticate('remember-me'));
app.use(app.router);
app.use(express.static(path.join(__dirname, 'public')));

// development only
if ('development' == app.get('env')) {
  app.use(express.errorHandler());
}

app.get('/', ensureAuthenticated, routes.index);
app.get('/users', ensureAuthenticated, user.list);

app.get('/login', routes.login);
app.post('/login',
  passport.authenticate('local', { failureRedirect: '/login', failureFlash: true }),
  function(req, res, next) {
    saveToken(1, function(token) {
      console.log(util.format('Login: Saving token \'%s\'', token));
      res.cookie('remember_me', token, { path: '/', httpOnly: true, maxAge: 120000 });
      return next();
    })
  },
  function(req, res) {
    res.redirect('/');
  }
);

app.get('/auth/oauth2', 
        passport.authenticate('oauth2', { failureRedirect: '/login' }),
        function(req, res) {
          console.log('/auth/oauth2');
          console.log(req.query);
          console.log(req.params);
          console.log(req.body);
          res.redirect('/');
        }
);

app.get('/oauth2callback',
        passport.authenticate('oauth2', { failureRedirect: '/login' }),
        function(req, res) {
          console.log('oauth2 return');
          console.log(req.query);
          console.log(req.params);
          console.log(req.body);
          res.redirect('/');
        }
);

/*
http.createServer(app).listen(app.get('port'), function(){
  console.log('Express server listening on port ' + app.get('port'));
});
*/

var https_options = {
  key: fs.readFileSync('crypto/rsa_private.pem'),
  cert: fs.readFileSync('crypto/rsa_cert.pem')
};

https.createServer(https_options, app).listen(app.get('port'), function(){
  console.log('Express server listening on port ' + app.get('port'));
});

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) { return next(); }
  res.redirect('/login');
};
