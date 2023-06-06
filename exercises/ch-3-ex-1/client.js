var express = require("express");
var request = require("sync-request");
var url = require("url");
var qs = require("qs");
var querystring = require("querystring");
var cons = require("consolidate");
var randomstring = require("randomstring");
var __ = require("underscore");
__.string = require("underscore.string");

var app = express();

app.engine("html", cons.underscore);
app.set("view engine", "html");
app.set("views", "files/client");

// authorization server information
var authServer = {
  authorizationEndpoint: "http://localhost:9001/authorize",
  tokenEndpoint: "http://localhost:9001/token",
};

// client information

/*
 * Add the client information in here
 */
var client = {
  client_id: "oauth-client-1",
  client_secret: "oauth-client-secret-1",
  redirect_uris: ["http://localhost:9000/callback"],
};

var protectedResource = "http://localhost:9002/resource";

var state = null;

var access_token = null;
var scope = null;

app.get("/", function (req, res) {
  res.render("index", { access_token: access_token, scope: scope });
});

app.get("/authorize", function (req, res) {
  /*
   * Send the user to the authorization server
   */

  state = randomstring.generate();
  const authorizeUrl = buildUrl(authServer.authorizationEndpoint, {
    response_type: "code",
    client_id: client.client_id,
    redirect_uri: client.redirect_uris[0],
    state,
  });
  res.redirect(authorizeUrl);
});

app.get("/callback", function (req, res) {
  /*
   * Parse the response from the authorization server and get a token
   */

  // Check state
  if (req.query.state != state) {
    res.render("error", { error: "State value did not match" });
    return;
  }

  const { code } = req.query;
  const form_data = qs.stringify({
    grant_type: "authorization_code",
    code,
    redirect_uri: client.redirect_uris[0],
  });
  const creds = encodeClientCredentials(client.client_id, client.client_secret);
  const headers = {
    "Content-Type": "application/x-www-form-urlencoded",
    Authorization: `Basic ${creds}`,
  };
  const tokRes = request("POST", authServer.tokenEndpoint, {
    body: form_data,
    headers,
  });
  const body = JSON.parse(tokRes.getBody());
  access_token = body.access_token;
  res.render("index", { access_token, scope });
});

app.get("/fetch_resource", function (req, res) {
  /*
   * Use the access token to call the resource server
   */

  if (!access_token) {
    res.render("error", { error: "Missing access token." });
    return;
  }

  const resource = request("POST", protectedResource, {
    headers: { Authorization: `Bearer ${access_token}` },
  });

  if (200 <= resource.statusCode && resource.statusCode < 300) {
    res.render("data", { resource: JSON.parse(resource.getBody()) });
    return;
  }

  res.render("error", {
    error: `Server returned response code: ${resource.statusCode}`,
  });
});

var buildUrl = function (base, options, hash) {
  var newUrl = url.parse(base, true);
  delete newUrl.search;
  if (!newUrl.query) {
    newUrl.query = {};
  }
  __.each(options, function (value, key, list) {
    newUrl.query[key] = value;
  });
  if (hash) {
    newUrl.hash = hash;
  }

  return url.format(newUrl);
};

var encodeClientCredentials = function (clientId, clientSecret) {
  return Buffer.from(
    querystring.escape(clientId) + ":" + querystring.escape(clientSecret)
  ).toString("base64");
};

app.use("/", express.static("files/client"));

var server = app.listen(9000, "localhost", function () {
  var host = server.address().address;
  var port = server.address().port;
  console.log("OAuth Client is listening at http://%s:%s", host, port);
});
