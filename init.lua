local aws = {}

function hexEncode(str)
  return (str:gsub('.', function (c)
    return string.format('%02x', string.byte(c))
  end))
end

function aws.VerifyArg(tbl, arg)
  if not tbl[arg] then error("'%s' required") end
end

function aws.GetSignedRequest(rq)

--  aws.verifyArg(rq, "AccessId")
--  aws.verifyArg(rq, "AccessKey")

  if not rq.QueryArgs then rq.QueryArgs = "" end
  if not rq.URI then rq.URI = "/" end
  if not rq.Scope then rq.Scope = rq.Service end

  local algorithm = "AWS4-HMAC-SHA256"
  local hash = "sha256"
  local requestMethod = "POST"

  local requestDateTime = os.date("!%Y%m%dT%H%M%SZ")
  local requestDate = os.date("!%Y%m%d")
  local serviceScope = string.format( "%s/%s/%s/aws4_request", requestDate, rq.Region, rq.Service )
  local credentialScope = string.format( "%s/%s/%s/aws4_request", requestDate, rq.Region, rq.Scope )

  local host = string.format( "%s.%s.amazonaws.com", rq.Service, rq.Region ) 
  
  local url = string.format("https://%s%s", host, rq.URI)

  local headers = {
    ["Content-Type"] = rq.ContentType,
    host = host,
    ["X-Amz-Date"] = requestDateTime,
  }
  -- list of headers needs to be lowercase and alphabetical
  local lowerCaseHeaders = {} 
  for k,v in pairs(headers) do
    table.insert(lowerCaseHeaders, string.lower(k))
  end
  table.sort(lowerCaseHeaders)
  
  local signedHeaders = table.concat(lowerCaseHeaders, ";")

  -- 
  -- Follows steps from https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
  -- to correctly sign our HTTP request to AWS
  
  --
  -- Create a canonical request
  -- https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
  --
  
  -- canonical request is in the form
  -- METHOD\n
  -- URI\n
  -- QUERYARGS\n
  -- HEADERS\n ( lower case and in alphabetical order )
  -- \n
  -- SIGNEDHEADERS\n
  -- HASHEDPAYLOAD
  
  local canonicalRequestTable = {}
  table.insert(canonicalRequestTable, requestMethod)
  table.insert(canonicalRequestTable, rq.URI)
  table.insert(canonicalRequestTable, rq.QueryArgs)
  
  -- the headers need to go in alphabetical order and lowercase
  -- first create a new table with lowercase keys with a companion
  -- list of keys. Then sort the keys and iterate them to add our 
  -- headers to the canonical request
  local lowerCaseHeaders = {} -- table of lower case keys to values
  local lowerCaseHeaderKeys = {} -- array of lower case keys we can sort
  for k,v in pairs(headers) do 
    lowerCaseHeaders[string.lower(k)] = v 
    table.insert(lowerCaseHeaderKeys, string.lower(k))
  end
  table.sort(lowerCaseHeaderKeys)
  
  for k,v in pairs(lowerCaseHeaderKeys) do
    table.insert(canonicalRequestTable, v..":"..lowerCaseHeaders[v])
  end
  table.insert(canonicalRequestTable, "")  -- blank line
  table.insert(canonicalRequestTable, signedHeaders)

  table.insert(canonicalRequestTable, hexEncode(Crypto.Digest(hash, rq.Payload)))
  
  canonicalRequest = table.concat(canonicalRequestTable, "\n")

  print("+CR")
  print(canonicalRequest)
  print("-cr")

  local hashedCanonicalRequest = hexEncode(Crypto.Digest(hash, canonicalRequest))
  --
  -- Create a string to sign
  -- https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
  --
  local stringToSign = string.format("%s\n%s\n%s\n%s", algorithm, requestDateTime, serviceScope, hashedCanonicalRequest)
  --
  -- Calculate signature 
  -- https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
  --
  local kDate = Crypto.HMAC(hash, "AWS4"..rq.AccessKey, requestDate)
  local kRegion = Crypto.HMAC(hash, kDate, rq.Region) 
  local kService = Crypto.HMAC(hash, kRegion, rq.Service)
  local kSigning = Crypto.HMAC(hash, kService, "aws4_request")
  local signature = hexEncode(Crypto.HMAC(hash, kSigning, stringToSign))
  --
  -- Add the signature to the HTTP request
  -- https://docs.aws.amazon.com/general/latest/gr/sigv4-add-signature-to-request.html
  --
  -- Authorization: algorithm Credential=access key ID/credential scope, SignedHeaders=SignedHeaders, Signature=signature
  headers["Authorization" ] = string.format("%s Credential=%s, SignedHeaders=%s, Signature=%s", algorithm, rq.AccessId.."/"..credentialScope, signedHeaders, signature )

  return {
    Url = url,
    Method = requestMethod,
    Headers = headers,
    Data = rq.Payload,
  }
end

return aws