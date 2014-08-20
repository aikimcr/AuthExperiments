
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

var DBFile = function() {
  this.db_ = {};

  this.load = function() {
    if (fs.existsSync(this.db_file_)) {
      var db_txt = fs.readFileSync(this.db_file_, {encoding: 'utf8'});
      this.db_ = db_txt ? JSON.parse(db_txt) : {};
    }
  };

  this.save = function() {
    var db_txt = JSON.stringify(this.db_);
    fs.writeFileSync(this.db_file_, db_txt, {encoding: 'utf8'});
  };

  this.getValue = function(key) {
    this.load();
    return this.db_[key];
  };

  this.putValue = function(key, value) {
    this.load();
    this.db_[key] = value;
    this.save();
  };

  this.deleteValue = function(key) {
    this.load();
    var result = this.db_[key];
    delete this.db_[key];
    this.save();
    return result;
  };

  this.find = function(match) {
    this.load();
    return this.db_.filter(match);
  };
};

var TokenList = function() {
  this.db_file_ = 'tokens.json';
  DBFile.apply(this, arguments);

  this.new_token_ = function() {
    return parseInt(Math.random() * parseInt('FFFFFFFF', 16), 10).toString(16).toUpperCase(); 
  };

  this.saveSession = function(uid, callback) {
    token = this.new_token_();
    this.putValue(token, uid);
    return callback(null, token);
  };

  this.consumeSession = function(token, callback) {
    var uid = this.deleteValue(token);

    if (uid != null) {
      callback(null, uid);
    } else {
      var msg = util.format('No matching token: \'%s\'', token);
      console.log(msg);
      callback(new Error(msg));
    }
  };
};
util.inherits(TokenList, DBFile);
var token_list = new TokenList();

var UserList = function() {
  this.db_file_ = 'users.json';
  DBFile.apply(this, arguments);

  this.createUser = function(user_info) {
    this.putValue(user_info.id, user_info);
  };

  this.updateUser = function(update_info) {
    var key = update_info.id;
    var old_value = this.getValue(key) || {};
    Object.keys(update_info).forEach(function(key) {
      old_value[key] = update_info[key];
    });
    this.putValue(key, old_value);
  };

  this.findByUsername = function(username, callback) {
    var result_list = this.find(function(user_info) {
      return ('username' in user_info && user_info.username == username);
    });
    if (result_list) {
      callback(null, result_list[0]);
    } else {
      callback(new Error("No user found"));
    }
  };
};
util.inherits(UserList, DBFile);
var user_list = new UserList();

user_list.createUser({id: 1, username: 'root', password: 'xyzzy'});
user_list.createUser({id: 2, username: 'branch', password: 'leaf'});

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

passport.use('local', new LocalStrategy(
  function(username, password, done) {
    user_list.findByUsername(username, function(err, user) {
      if (err) {
        return done(null, false, { message: 'No user found' });
      } else if ('password' in user && user.password == password) {
        return done(null, false, { messagae: 'Login incorrect' });
      } else {
        return done(null, user.id)
      }
    });
  }
));

passport.use('remember-me', new RememberMeStrategy(
  function(token, done) {
    token_list.consumeSession(token, function(err, uid) {
      console.log(util.format('Consume token \'%s\'', token));
      if (err) {
        console.log(err);
        done(null, false, { msg: err.toString() });
      } else {
        var user = user_list.getValue(uid);
        oauth2_client.setCredentials(user.google_auth);
        done(null, uid);
      }
    });
  },
  function(user, done) {
    token_list.saveSession(user, function(err, token) {
      if (err) {
        console.log(err);
        done(null, false, { msg: err.toString() });
      } else {
        console.log(util.format('Strategy: Saving token \'%s\'', token));
        return done(null, token);
      }
    });
  }
));

passport.use('google_oauth2', new OAuth2Strategy({
    authorizationURL: google_info.authorization_url,
    tokenURL: google_info.token_url,
    clientID: google_info.client_id,
    clientSecret: google_info.client_secret,
    callbackURL: "https://localhost:4000/auth/result/google_oauth2",
    scope: google_info.scope.join(' '),
  },
  function(accessToken, refreshToken, profile, done) {
   return done(null, -1, { access_token: accessToken });
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

function saveSession(res, next, user) {
  token_list.saveSession(user, function(err, token) {
    if (err) {
      return res.send(500, err);
    } else {
      console.log(util.format('Login: Saving token \'%s\'', token));
      res.cookie('remember_me', token, { path: '/', httpOnly: true, maxAge: 120000 });
      return next();
    }
  });
}

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
    saveSession(res, next, req.session.passport.user);
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
      google.plus('v1').people.get({ userId: 'me' }, function(err, response) {
        if (err) {
          console.log(err);
          res.send(500, err);
        } else {
          console.log(response);
          user_list.createUser({
            id: response.id,
            google_auth: tokens,
          });
          saveSession(res, next, response.id);
        }
      });
    }
  });
}, function(req, res) {
/*
  var calendar = google.calendar({ version: 'v3' });
  var user_id = 'me';
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
*/
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
