var express = require("express");
var bodyParser = require("body-parser");
var request = require("sync-request");
var url = require("url");
var qs = require("qs");
var querystring = require("querystring");
var cons = require("consolidate");
var randomstring = require("randomstring");
var base64url = require("base64url");

var app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.engine("html", cons.underscore);
app.set("view engine", "html");
app.set("views", "files/client");

// authorization server information
var authServer = {
  authorizationEndpoint: "http://localhost:9001/authorize",
  tokenEndpoint: "http://localhost:9001/token",
};

// client information

var client = {
  client_id: "oauth-client-1",
  client_secret: "oauth-client-secret-1",
  scope: "foo bar",
};

//var client = {};

var protectedResource = "http://localhost:9002/resource";

var state = null;

var access_token = null;
var scope = null;

app.get("/", function (req, res) {
  res.render("index", { access_token: access_token, scope: scope });
});

app.get("/authorize", function (req, res) {
  access_token = null;
  scope = null;

  /*
   * Implement the client credentials flow here
   */
  const formData = qs.stringify({
    grant_type: "client_credentials",
    scope: client.scope,
  });
  const creds = encodeClientCredentials(client.client_id, client.client_secret);
  const headers = {
    "Content-Type": "application/x-www-form-urlencoded",
    Authorization: `Basic ${creds}`,
  };
  const tokRes = request("POST", authServer.tokenEndpoint, {
    body: formData,
    headers,
  });

  if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
    const body = JSON.parse(tokRes.getBody());
    access_token = body.access_token;
    scope = body.scope;
    res.render("index", { access_token, scope });
  } else {
    res.render("error", {
      error: `Unable to fetch access token, server response: ${tokRes.statusCode}`,
    });
  }
});

app.get("/fetch_resource", function (req, res) {
  if (!access_token) {
    res.render("error", { error: "Missing access token." });
    return;
  }

  console.log("Making request with access token %s", access_token);

  var headers = {
    Authorization: "Bearer " + access_token,
    "Content-Type": "application/x-www-form-urlencoded",
  };

  var resource = request("POST", protectedResource, { headers: headers });

  if (resource.statusCode >= 200 && resource.statusCode < 300) {
    var body = JSON.parse(resource.getBody());
    res.render("data", { resource: body });
    return;
  } else {
    access_token = null;
    res.render("error", {
      error: "Server returned response code: " + resource.statusCode,
    });
    return;
  }
});

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
