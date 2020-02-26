function validateToken (token) {
 const header = jwt.decode(token)
 const now = Math.floor(Date.now() / 1000)
 return header && header.exp > now
}

async function getSession (url) {
 const token = await loadToken(url)
 if (!token) return null
 const header = jwt.decode(token)
 if (!header) return null
 const now = Math.floor(Date.now() / 1000)
 if (header.exp <= now) return null
 return header
}


static decodeRptToken(rptTokenResponse) {
    const rptToken = JSON.parse(rptTokenResponse).rpt;
    const rpt = jwt.decode(rptToken);
    let permissions = [];
    (rpt.authorization.permissions || []).forEach(p => permissions.push({
      scopes: p.scopes,
      resource: p.resource_set_name
    }));
    return {
      userName: rpt.preferred_username,
      roles: rpt.realm_access.roles,
      permissions: permissions
    };
  }
  
  getUserName(request) {
    return this.getAccessToken(request)
      .then(token => Promise.resolve(jwt.decode(token).preferred_username));
  }
  
  async function getSessions () {
 let tokens = {}
 try {
  const data = await readFile(credentialsPath)
  tokens = JSON.parse(data)
 } catch (err) {}
 const sessions = {}
 Object.keys(tokens).forEach((url) => {
  sessions[url] = validateToken(tokens[url])
   ? jwt.decode(tokens[url])
   : null
 })
 return sessions
}


function validateAskPermission (token) {
 const header = jwt.decode(token)

 return validateToken(token) && header[ASK_CLAIM_KEY]
}

src/auth.ts/AuthModule/verifyJWT
const decoded = jsonwebtoken.decode(jwt, { complete: true });

  
 controllers/user.server.controller.js/getToken
var getToken = function(req, next) {
  var bearerToken;
  var bearerHeader = req.headers["authorization"];
  if (typeof bearerHeader !== 'undefined') {
    var bearer = bearerHeader.split(" ");
    bearerToken = bearer[1];
    var token = jwt.decode(bearerToken, {complete: true});
    try {
      if ((token.payload.exp <= moment().unix())) {
        next('token_expire')
      } else {
        //verificando mismo host de usuario
        if (token.payload.host !== requestIp.getClientIp(req)) {
          next('token_host_invalid')
        } else {
          next(null, token.payload)
        }
      }
    } catch (e) {
      next('token_host_invalid')
    }            

  } else {
    return next('token_not_found')
  }    
}

  lib/strategy.js/CognitoExpress/validate
validate(token, callback) {
    const p = this.promise.then(() => {
      let decodedJwt = jwt.decode(token, { complete: true });
      
// set the token in the Authentication componenent state
  // this is naive, and will work with whatever token is returned. under no circumstances should you use this logic to trust private data- you should always verify the token on the backend before displaying that data. 
  setToken(token,opaque_id){
    let isMod = false
    let role = ""
    let user_id = ""

    try {
      let decoded = jwt.decode(token)
      
      if(decoded.role === 'broadcaster' || decoded.role === 'moderator'){
        isMod = true
      }

      user_id = decoded.user_id
      role = decoded.role
    } catch (e) {
      token=''
      opaque_id=''
    }

    this.state={
      token,
      opaque_id,
      isMod,
      user_id,
      role
    }
  }
  
  
  server/controllers/user.server.controller.js/getToken
var getToken = function(req, next) {
  var bearerToken;
  var bearerHeader = req.headers["authorization"];
  if (typeof bearerHeader !== 'undefined') {
    var bearer = bearerHeader.split(" ");
    bearerToken = bearer[1];
    var token = jwt.decode(bearerToken, {complete: true});
    try {
      if ((token.payload.exp <= moment().unix())) {
        next('token_expire')
      } else {
        //verificando mismo host de usuario
        if (token.payload.host !== requestIp.getClientIp(req)) {
          next('token_host_invalid')
        } else {
          next(null, token.payload)
        }
      }
    } catch (e) {
      next('token_host_invalid')
    }            

  } else {
    return next('token_not_found')
  }    
}
  
