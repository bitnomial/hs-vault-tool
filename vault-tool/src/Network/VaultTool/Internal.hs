{-# LANGUAGE GADTs #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.VaultTool.Internal (
    VaultRequest,
    runVaultRequestAuthenticated,
    runVaultRequestAuthenticated_,
    runVaultRequestUnauthenticated,
    runVaultRequestUnauthenticated_,
    newGetRequest,
    newPostRequest,
    newPutRequest,
    newDeleteRequest,
    newListRequest,
    withStatusCodes,
) where

import Control.Exception (throwIO)
import Control.Monad (unless, void)
import Data.Aeson
import qualified Data.ByteString.Lazy as BL
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import Network.HTTP.Client
import Network.HTTP.Types.Method
import Network.HTTP.Types.Status

import Network.VaultTool.Types

data VaultRequest a = VaultRequest
    { vrMethod :: Method
    , vrPath :: Text
    , vrBody :: Maybe a
    , vrExpectedStatuses :: [Int]
    }

newRequest :: Method -> Text -> Maybe a -> VaultRequest a
newRequest method path mbBody =
    VaultRequest
        { vrMethod = method
        , vrPath = path
        , vrBody = mbBody
        , vrExpectedStatuses = [200]
        }

newGetRequest :: Text -> VaultRequest ()
newGetRequest path = newRequest "GET" path Nothing

newPostRequest :: Text -> Maybe a -> VaultRequest a
newPostRequest = newRequest "POST"

newPutRequest :: Text -> Maybe a -> VaultRequest a
newPutRequest = newRequest "PUT"

newDeleteRequest :: Text -> VaultRequest ()
newDeleteRequest path = newRequest "DELETE" path Nothing

newListRequest :: Text -> VaultRequest ()
newListRequest path = newRequest "LIST" path Nothing

withStatusCodes :: [Int] -> VaultRequest a -> VaultRequest a
withStatusCodes statusCodes req = req{vrExpectedStatuses = statusCodes}

vaultRequest :: ToJSON a => Manager -> VaultAddress -> Maybe VaultAuthToken -> VaultRequest a -> IO BL.ByteString
vaultRequest manager addr mbToken VaultRequest{vrMethod, vrPath, vrBody, vrExpectedStatuses} = do
    initReq <- case parseRequest absolutePath of
        Nothing -> throwIO $ VaultException_InvalidAddress vrMethod vrPath
        Just initReq -> pure initReq
    let reqBody = maybe BL.empty encode vrBody
        req = initReq
            { method = vrMethod
            , requestBody = RequestBodyLBS reqBody
            , requestHeaders = requestHeaders initReq ++ authTokenHeader mbToken
            }
    rsp <- httpLbs req manager
    let s = statusCode (responseStatus rsp)
    unless (s `elem` vrExpectedStatuses) $ do
        throwIO $ VaultException_BadStatusCode vrMethod vrPath reqBody s (responseBody rsp)
    pure (responseBody rsp)
  where
    absolutePath = T.unpack $ T.intercalate "/" [unVaultAddress addr, "v1", vrPath]

    authTokenHeader = maybe mempty toHeader
      where
        toHeader (VaultAuthToken token) = [("X-Vault-Token", T.encodeUtf8 token)]

runVaultRequestAuthenticated :: (FromJSON b, ToJSON a) => VaultConnection Authenticated -> VaultRequest a -> IO b
runVaultRequestAuthenticated conn req =
    runAuthenticatedVaultConnection (\m a t -> runVaultRequest m a (Just t) req) conn

runVaultRequestUnauthenticated :: (FromJSON b, ToJSON a) => VaultConnection c -> VaultRequest a -> IO b
runVaultRequestUnauthenticated conn req =
    runAnyVaultConnection (\m a -> runVaultRequest m a Nothing req) conn

runVaultRequest :: (FromJSON b, ToJSON a) => Manager -> VaultAddress -> Maybe VaultAuthToken -> VaultRequest a -> IO b
runVaultRequest manager addr mbToken req@VaultRequest{vrMethod, vrPath} = do
    rspBody <- vaultRequest manager addr mbToken req
    case eitherDecode' rspBody of
        Left err -> throwIO $ VaultException_ParseBodyError vrMethod vrPath rspBody (T.pack err)
        Right x -> pure x

runVaultRequestAuthenticated_ :: (ToJSON a) => VaultConnection Authenticated -> VaultRequest a -> IO ()
runVaultRequestAuthenticated_ conn req =
    void $ runAuthenticatedVaultConnection (\m a t -> vaultRequest m a (Just t) req) conn

runVaultRequestUnauthenticated_ :: (ToJSON a) => VaultConnection a -> VaultRequest a -> IO ()
runVaultRequestUnauthenticated_ conn req =
    void $ runAnyVaultConnection (\m a -> vaultRequest m a Nothing req) conn
