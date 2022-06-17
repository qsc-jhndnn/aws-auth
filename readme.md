# AWS Authentication module

### _Module for authenticating with AWS API services_
 
This module implements the low level message signing requirments of authenticating AWS Services calls. 

### `GetSignedRequest(request)`
Returns a table which contains the signed request that can be passed directly to `HttpClient`. The request arguement has the following fields

* `AccessId` - AWS Access ID
* `AccessKey` - AWS Access Key
* `ContentType` - Content type of payload. Depends on service, ie `"application/json"`
* `Region` - AWS Server region - ie `"us-east-1"`
* `Service` - AWS Service - ie `"email"`
* `URI` - Optional URL ( some services don't require this )

Example of signing message for use with SES email service


```
aws = require("aws-auth")

local destination = "to@foo.com"
local source = "from@bar.com"
local message = "this is a message"

local encodedMessage = Crypto.Base64Encode(message)
-- trim off trailing =s if it exists
encodedMessage = string.gsub(encodedMessage, "=", "")

local payloadString = "Action=SendRawEmail"
payloadString = payloadString..string.format("&Destinations.member.1=%s", HttpClient.EncodeString(destination))
payloadString = payloadString..string.format("&RawMessage.Data=%s", encodedMessage)
payloadString = payloadString..string.format("&Source=%s", HttpClient.EncodeString(source))

local rq = {  
  Region = "us-east-1",
  Service = "email",
  ContentType = "application/x-www-form-urlencoded",
  Payload = payloadString,
  AccessId = AWS_ACCESS_ID,
  AccessKey = AWS_ACCESS_KEY
}

local signedRequest = aws.GetSignedRequest(rq)

signedRequest.EventHandler = function(_, c, d, e ) data.EventHandler(c, d, e ) end

HttpClient.Upload(signedRequest)
```



 
