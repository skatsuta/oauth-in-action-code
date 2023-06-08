var express = require("express");
var url = require("url");
var bodyParser = require("body-parser");
var randomstring = require("randomstring");
var cons = require("consolidate");
var nosql = require("nosql").load("database.nosql");
var querystring = require("querystring");
var __ = require("underscore");
__.string = require("underscore.string");

var app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for the token endpoint)

app.engine("html", cons.underscore);
app.set("view engine", "html");
app.set("views", "files/authorizationServer");
app.set("json spaces", 4);

// authorization server information
var authServer = {
  authorizationEndpoint: "http://localhost:9001/authorize",
  tokenEndpoint: "http://localhost:9001/token",
};

// client information
var clients = [
  /*
   * Enter client information here
   */
  {
    client_id: "oauth-client-1",
    client_secret: "oauth-client-secret-1",
    redirect_uris: ["http://localhost:9000/callback"],
  },
];

var codes = {};

var requests = {};

var getClient = function (clientId) {
  return __.find(clients, function (client) {
    return client.client_id == clientId;
  });
};

app.get("/", function (req, res) {
  res.render("index", { clients: clients, authServer: authServer });
});

app.get("/authorize", function (req, res) {
  /*
   * Process the request, validate the client, and send the user to the approval page
   */

  const { query } = req;
  const client = getClient(query.client_id);
  if (!client) {
    res.render("error", { error: "Unknown client" });
    return;
  } else if (client.redirect_uris.includes(query.redirect_uris)) {
    res.render("error", { error: "Invalid redirect URI" });
    return;
  }

  const reqid = randomstring.generate(8); // CSRF token
  requests[reqid] = query;

  res.render("approve", { client, reqid });
});

app.post("/approve", function (req, res) {
  /*
   * Process the results of the approval page, authorize the client
   */

  const { reqid } = req.body;
  const query = requests[reqid];
  delete requests[reqid];

  if (!query) {
    res.render("error", { error: "No matching authorization request" });
    return;
  }

  if (!req.body.approve) {
    const url = buildUrl(query.redirect_uri, { error: "access_denied" });
    res.redirect(url);
    return;
  }

  if (query.response_type !== "code") {
    const url = buildUrl(query.redirect_uri, {
      error: "unsupported_response_type",
    });
    res.redirect(url);
    return;
  }

  // Generate authorization code
  const code = randomstring.generate(8);
  codes[code] = { request: query };

  const url = buildUrl(query.redirect_uri, { code, state: query.state });
  res.redirect(url);
});

app.post("/token", function (req, res) {
  /*
   * Process the request, issue an access token
   */

  // Get Authorization header value
  let clientCredentials, clientId, clientSecret;
  const auth = req.headers["authorization"];
  if (auth) {
    clientCredentials = decodeClientCredentials(auth);
    clientId = clientCredentials.id;
    clientSecret = clientCredentials.secret;
  }

  // Check if client secret is in the form body
  const { body } = req;
  if (body.client_id) {
    if (clientId || clientSecret) {
      res.status(401).json({ error: "invalid_client" });
      return;
    }

    clientId = body.client_id;
    clientSecret = body.client_secret;
  }

  // Check if client is valid
  const client = getClient(clientId);
  if (!client) {
    res.status(401).json({ error: "invalid_client" });
    return;
  } else if (clientSecret !== client.client_secret) {
    res.status(401).json({ error: "invalid_client" });
    return;
  }

  // Check grant type
  if (body.grant_type !== "authorization_code") {
    res.status(400).json({ error: "unsupported_grant_type" });
    return;
  }

  const code = codes[body.code];
  if (!code) {
    res.status(400).json({ error: "invalid_grant" });
    return;
  }

  // Check authorization code
  delete codes[body.code];
  if (clientId !== code.request.client_id) {
    res.status(400).json({ error: "invalid_grant" });
    return;
  }

  // Generate and store access token
  const accessToken = randomstring.generate();
  nosql.insert({ access_token: accessToken, client_id: clientId });

  res.status(200).json({ access_token: accessToken, token_type: "Bearer" });
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

var decodeClientCredentials = function (auth) {
  var clientCredentials = Buffer.from(auth.slice("basic ".length), "base64")
    .toString()
    .split(":");
  var clientId = querystring.unescape(clientCredentials[0]);
  var clientSecret = querystring.unescape(clientCredentials[1]);
  return { id: clientId, secret: clientSecret };
};

app.use("/", express.static("files/authorizationServer"));

// clear the database
nosql.clear();

var server = app.listen(9001, "localhost", function () {
  var host = server.address().address;
  var port = server.address().port;

  console.log(
    "OAuth Authorization Server is listening at http://%s:%s",
    host,
    port
  );
});
