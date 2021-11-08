{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

{- | A library for working with Vault's KeyValue version 2 secrets engine

 Unless otherwise specified, all IO functions in this module may
 potentially throw 'HttpException' or 'VaultException'
-}
module Network.VaultTool.KeyValueV2 (
    VaultSecretVersion (..),
    VaultSecretVersionMetadata (..),
    vaultWrite,
    vaultRead,
    vaultReadVersion,
    vaultDelete,
    vaultList,
    isFolder,
    vaultListRecursive,
) where

import Control.Applicative (optional)
import Data.Aeson (
    FromJSON,
    ToJSON,
    object,
    parseJSON,
    toJSON,
    withObject,
    (.:),
    (.=),
 )
import Data.Text (Text)
import qualified Data.Text as T
import Data.Time (UTCTime)

import Network.VaultTool.Internal (
    newDeleteRequest,
    newGetRequest,
    newListRequest,
    newPostRequest,
    runVaultRequestAuthenticated,
    runVaultRequestAuthenticated_,
    withStatusCodes,
 )
import Network.VaultTool.Types (
    VaultConnection,
    Authenticated,
    VaultMountedPath (..),
    VaultSearchPath (..),
    VaultSecretPath (..),
 )

{- | <https://www.vaultproject.io/api-docs/secret/kv/kv-v2#sample-response-1>
-}
data VaultSecretVersion a = VaultSecretVersion
    { vsvData :: a
    , vsvMetadata :: VaultSecretVersionMetadata
    }
    deriving (Show)

instance FromJSON a => FromJSON (VaultSecretVersion a) where
    parseJSON = withObject "VaultSecretVersion" $ \v ->
        VaultSecretVersion
            <$> v .: "data"
            <*> v .: "metadata"

{- | <https://www.vaultproject.io/api-docs/secret/kv/kv-v2#sample-response-1>
-}
data VaultSecretVersionMetadata = VaultSecretVersionMetadata
    { vsvmCreatedTime :: UTCTime
    , vsvmDeletionTime :: Maybe UTCTime
    , vsvmDestroyed :: Bool
    , vsvmVersion :: Int
    }
    deriving (Show)

instance FromJSON VaultSecretVersionMetadata where
    parseJSON = withObject "VaultSecretVersionMetadata" $ \v ->
        VaultSecretVersionMetadata
            <$> v .: "created_time"
            <*> optional (v .: "deletion_time")
            <*> v .: "destroyed"
            <*> v .: "version"

vaultRead ::
    FromJSON a =>
    VaultConnection Authenticated ->
    VaultSecretPath ->
    IO (VaultSecretVersion a)
vaultRead conn path = vaultReadVersion conn path Nothing

vaultReadVersion ::
    FromJSON a =>
    VaultConnection Authenticated ->
    VaultSecretPath ->
    Maybe Int ->
    IO (VaultSecretVersion a)
vaultReadVersion conn (VaultSecretPath (mountedPath, searchPath)) version =
    runVaultRequestAuthenticated conn (newGetRequest path) >>= \(DataWrapper x) -> pure x
  where
    path = vaultActionPath ReadSecretVersion mountedPath searchPath <> queryParams
    queryParams = case version of
        Nothing -> ""
        Just n -> "?version=" <> T.pack (show n)

newtype DataWrapper a = DataWrapper a

instance ToJSON a => ToJSON (DataWrapper a) where
    toJSON (DataWrapper x) = object ["data" .= x]

instance FromJSON a => FromJSON (DataWrapper a) where
    parseJSON = withObject "DataWrapper" $ fmap DataWrapper . (.: "data")

{- | <https://www.vaultproject.io/docs/secrets/generic/index.html>
-}
vaultWrite :: ToJSON a => VaultConnection Authenticated -> VaultSecretPath -> a -> IO ()
vaultWrite conn (VaultSecretPath (mountedPath, searchPath)) = do
    runVaultRequestAuthenticated_ conn
        . withStatusCodes [200, 204]
        . newPostRequest (vaultActionPath WriteSecret mountedPath searchPath)
        . Just
        . DataWrapper

newtype VaultListResult = VaultListResult [Text]

instance FromJSON VaultListResult where
    parseJSON = withObject "VaultListResult" $ \v -> do
        data_ <- v .: "data"
        keys <- data_ .: "keys"
        pure (VaultListResult keys)

{- | <https://www.vaultproject.io/docs/secrets/generic/index.html>

 This will normalise the results to be full secret paths.

 Will return only secrets that in the are located in the folder hierarchy
 directly below the given folder.

 Use 'isFolder' to check if whether each result is a secret or a subfolder.

 The order of the results is unspecified.

 To recursively retrieve all of the secrets use 'vaultListRecursive'
-}
vaultList :: VaultConnection Authenticated -> VaultSecretPath -> IO [VaultSecretPath]
vaultList conn (VaultSecretPath (VaultMountedPath mountedPath, VaultSearchPath searchPath)) = do
    let path = vaultActionPath ListSecrets (VaultMountedPath mountedPath) (VaultSearchPath searchPath)
    VaultListResult keys <-
        runVaultRequestAuthenticated conn $
            newListRequest path
    pure $ map (VaultSecretPath . fullSecretPath) keys
  where
    fullSecretPath key = (VaultMountedPath mountedPath, VaultSearchPath (withTrailingSlash `T.append` key))
    withTrailingSlash
        | T.null searchPath = ""
        | T.last searchPath == '/' = searchPath
        | otherwise = searchPath `T.snoc` '/'

{- | Recursively calls 'vaultList' to retrieve all of the secrets in a folder
 (including all subfolders and sub-subfolders, etc...)

 There will be no folders in the result.

 The order of the results is unspecified.
-}
vaultListRecursive :: VaultConnection Authenticated -> VaultSecretPath -> IO [VaultSecretPath]
vaultListRecursive conn location = do
    paths <- vaultList conn location
    flip concatMapA paths $ \path -> do
        if isFolder path
            then vaultListRecursive conn path
            else pure [path]
  where
    concatMapA f = fmap concat . traverse f

{- | Does the path end with a '/' character?

 Meant to be used on the results of 'vaultList'
-}
isFolder :: VaultSecretPath -> Bool
isFolder (VaultSecretPath (_, VaultSearchPath searchPath))
    | T.null searchPath = False
    | otherwise = T.last searchPath == '/'

-- | <https://www.vaultproject.io/docs/secrets/generic/index.html>
vaultDelete :: VaultConnection Authenticated -> VaultSecretPath -> IO ()
vaultDelete conn (VaultSecretPath (mountedPath, searchPath)) = do
    runVaultRequestAuthenticated_ conn
        . withStatusCodes [204]
        $ newDeleteRequest (vaultActionPath HardDeleteSecret mountedPath searchPath)

data VaultAction
    = WriteConfig
    | ReadConfig
    | ReadSecretVersion
    | WriteSecret
    | SoftDeleteLatestSecret
    | SoftDeleteSecretVersions
    | UndeleteSecretVersions
    | DestroySecretVersions
    | ListSecrets
    | ReadSecretMetadata
    | WriteSecreteMetadata
    | HardDeleteSecret

vaultActionPath :: VaultAction -> VaultMountedPath -> VaultSearchPath -> Text
vaultActionPath action (VaultMountedPath mountedPath) (VaultSearchPath searchPath) =
    T.intercalate "/" [mountedPath, actionPrefix action, searchPath]
  where
    actionPrefix = \case
        WriteConfig -> "config"
        ReadConfig -> "config"
        ReadSecretVersion -> "data"
        WriteSecret -> "data"
        SoftDeleteLatestSecret -> "data"
        SoftDeleteSecretVersions -> "delete"
        UndeleteSecretVersions -> "undelete"
        DestroySecretVersions -> "destroy"
        ListSecrets -> "metadata"
        ReadSecretMetadata -> "metadata"
        WriteSecreteMetadata -> "metadata"
        HardDeleteSecret -> "metadata"
