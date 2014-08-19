
/**
 * Module dependencies.
 */

var express = require('express');
var flash = require('connect-flash');
var fs = require('fs');
var http = require('http');
var https = require('https');
var path = require('path');
var util = require('util');

var passport = require('passport');
var RememberMeStrategy = require('passport-remember-me').Strategy;
var LocalStrategy = require('passport-local').Strategy;
var OAuth2Strategy = require('passport-oauth2').Strategy;
var SAMLStrategy = require('passport-saml').Strategy;

var google = require('googleapis');
var GoogleOAuth2 = google.auth.OAuth2;

var routes = require('./routes');
var user = require('./routes/user');

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

var google_info = {
  api_key: 'AIzaSyAJfr0-IXoEqpNSlUhpg6kqbTenUAIckHo',
  authorization_url: 'https://accounts.google.com/o/oauth2/auth',
  token_url: 'https://accounts.google.com/o/oauth2/token',
  client_id: '922391096653-1slbbcf5ujrrfn5oeap0a0acvmr626l7.apps.googleusercontent.com',
  client_secret: 'e5Lfe_nTegO37xPjqLjaYXiD',
  scope: [
    'openid',
    'https://www.googleapis.com/auth/plus.login',
    'https://www.googleapis.com/auth/plus.me',
    'https://www.googleapis.com/auth/calendar'
  ]
};

var oauth2_client = new GoogleOAuth2(
  google_info.client_id,
  google_info.client_secret,
  'https://localhost:4000/auth/result/google_api'
);
google.options({auth: oauth2_client});

passport.use('google_oauth2', new OAuth2Strategy({
    authorizationURL: google_info.authorization_url,
    tokenURL: google_info.token_url,
    clientID: google_info.client_id,
    clientSecret: google_info.client_secret,
    callbackURL: "https://localhost:4000/auth/result/google_oauth2",
    scope: google_info.scope.join(' '),
  },
  function(accessToken, refreshToken, profile, done) {
    return done(null, 1, { access_token: accessToken });
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

app.get('/auth/google_oauth2', 
        passport.authenticate('google_oauth2', { failureRedirect: '/login' }),
        function(req, res) { res.redirect('/'); }
);

app.get('/auth/result/google_oauth2',
        passport.authenticate('oauth2', { failureRedirect: '/login' }),
        function(req, res) { res.redirect('/'); }
);

app.get('/auth/google_api', function(req, res) {
  var url = oauth2_client.generateAuthUrl({
    access_type: 'offline', // 'online' (default) or 'offline' (gets refresh_token)
    scope: google_info.scope // If you only need one scope you can pass it as string
  });
  res.redirect(url);
});

app.get('/auth/result/google_api', function(req, res, next) {
  var auth_code = req.query.code;
  oauth2_client.getToken(auth_code, function(err, tokens) {
    if (err) {
      res.send(500, util.inspect(err));
    } else {
      oauth2_client.setCredentials(tokens);
      saveToken(1, function(token) {
        console.log(util.format('Login: Saving token \'%s\'', token));
        res.cookie('remember_me', token, { path: '/', httpOnly: true, maxAge: 120000 });
        return next();
      })
    }
  });
}, function(req, res) {
  var plus = google.plus('v1');
  var calendar = google.calendar({ version: 'v3' });
  var user_id = 'me';
  plus.people.get({ userId: user_id}, function(err, response) {
    if (err) {
      console.log(err);
    } else {
      console.log(response);
    }
  });
  calendar.calendarList.list({ userId: user_id}, function(err, response) {
    if (err) {
      console.log(err);
    } else {
      console.log(response);
    }
  });
  calendar.calendars.get({ userId: user_id, calendarId: 'aikimcr@gmail.com' }, function(err, response) {
    if (err) {
      console.log(err);
    } else {
      console.log(response);
    }
  });
  res.redirect('/');
});

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
