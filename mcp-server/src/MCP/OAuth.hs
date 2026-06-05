{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PackageImports #-}

-- | OAuth 2.1 / MCP token primitives: hashing, opaque-token minting and PKCE
-- verification. Pure crypto with no storage and no framework coupling — the
-- @ihp-mcp@ glue layer persists what these produce.
--
-- Tokens are stored hashed (SHA-256 over UTF-8 bytes), so a DB compromise
-- never leaks live credentials. The plaintext is shown to the client exactly
-- once at mint time.
module MCP.OAuth
    ( -- * Hashing
      hashToken
      -- * Minting
    , generateSecret
    , generateClientId
    , generateAuthCode
    , generateAccessToken
    , generateRefreshToken
      -- * PKCE
    , verifyPkceS256
      -- * Lifetimes (seconds)
    , accessTokenLifetimeSeconds
    , refreshTokenLifetimeSeconds
    , authCodeLifetimeSeconds
    ) where

import Prelude
import Data.Text (Text)
import qualified Data.Text.Encoding as TextEnc
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import qualified Data.ByteArray as ByteArray
import qualified "base64-bytestring" Data.ByteString.Base64.URL as B64Url
import "crypton" Crypto.Hash (hashWith, SHA256 (..), Digest)
import "crypton" Crypto.Random (getRandomBytes)

------------------------------------------------------------
-- Lifetimes
------------------------------------------------------------

accessTokenLifetimeSeconds :: Int
accessTokenLifetimeSeconds = 3600

-- | 30 days, sliding (each refresh issues a new pair).
refreshTokenLifetimeSeconds :: Int
refreshTokenLifetimeSeconds = 30 * 24 * 3600

-- | OAuth 2.1 says "no longer than 10 minutes, recommended <= 1 minute".
authCodeLifetimeSeconds :: Int
authCodeLifetimeSeconds = 600

------------------------------------------------------------
-- Minting
------------------------------------------------------------

-- | 32 bytes of CSPRNG entropy, base64url-no-pad. The building block for every
-- opaque token below.
generateSecret :: IO Text
generateSecret = do
    bytes <- getRandomBytes 32
    pure (b64UrlNoPad bytes)

-- | Mint a new @client_id@ for a Dynamic Client Registration. Public clients,
-- so no secret. The prefix lets us pattern-match in support cases.
generateClientId :: IO Text
generateClientId = ("mcp_client_" <>) <$> generateSecret

-- | Authorization code. Returns @(plaintext, hash)@; persist only the hash.
generateAuthCode :: IO (Text, ByteString)
generateAuthCode = prefixed "mcp_code_"

generateAccessToken :: IO (Text, ByteString)
generateAccessToken = prefixed "mcp_oauth_"

generateRefreshToken :: IO (Text, ByteString)
generateRefreshToken = prefixed "mcp_refresh_"

prefixed :: Text -> IO (Text, ByteString)
prefixed prefix = do
    secret <- generateSecret
    let plaintext = prefix <> secret
    pure (plaintext, hashToken plaintext)

------------------------------------------------------------
-- PKCE
------------------------------------------------------------

-- | RFC 7636 §4.6 verification: @BASE64URL-NO-PAD(SHA256(verifier)) == challenge@.
-- Constant-time compare. Returns 'False' on any length mismatch.
verifyPkceS256 :: Text -> Text -> Bool
verifyPkceS256 verifier challenge =
    let computed = b64UrlNoPad (sha256 verifier)
        challengeBytes = TextEnc.encodeUtf8 challenge
        computedBytes = TextEnc.encodeUtf8 computed
    in BS.length challengeBytes == BS.length computedBytes
       && ByteArray.constEq challengeBytes computedBytes

------------------------------------------------------------
-- Hashing
------------------------------------------------------------

-- | SHA-256 over the UTF-8 bytes of a token. Stored in @api_tokens.token_hash@
-- / @oauth_authorization_codes.code_hash@.
hashToken :: Text -> ByteString
hashToken = sha256

------------------------------------------------------------
-- internals
------------------------------------------------------------

sha256 :: Text -> ByteString
sha256 t =
    let digest :: Digest SHA256 = hashWith SHA256 (TextEnc.encodeUtf8 t)
    in BS.pack (ByteArray.unpack digest)

b64UrlNoPad :: ByteString -> Text
b64UrlNoPad = TextEnc.decodeUtf8 . stripPad . B64Url.encode
  where
    stripPad = BS.takeWhile (/= 0x3D)  -- '=' is 0x3D
