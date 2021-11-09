{-# LANGUAGE GADTs #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.VaultTool.Types (
    VaultAddress (..),
    VaultAppRoleId (..),
    VaultAppRoleSecretId (..),
    VaultAppRoleSecretIdAccessor (..),
    VaultAuthToken (..),
    VaultConnection (..),
    Authenticated,
    Unauthenticated,
    authenticatedVaultConnection,
    unauthenticatedVaultConnection,
    VaultException (..),
    VaultMountedPath (..),
    VaultSearchPath (..),
    VaultSecretPath (..),
    VaultUnsealKey (..),
) where

import Control.Exception (Exception)
import Data.Aeson (FromJSON, ToJSON, (.:), (.=), object, parseJSON, toJSON, withObject)
import Data.ByteString (ByteString)
import Data.Text (Text)
import qualified Data.ByteString.Lazy as BL
import Network.HTTP.Client (Manager)

-- | The APIs exported by this library expect a 'VaultConnection' which is used to know where a vault server is and how
-- to talk to it. The type parameter is used to distinguish between 'Unauthenticated' and 'Authenticated' requests. When
-- a function takes a polymorphic connection (VaultConnection a), either type of connection can be used.
data VaultConnection a where
    UnauthenticatedVaultConnection :: Manager -> VaultAddress -> VaultConnection Unauthenticated
    AuthenticatedVaultConnection :: Manager -> VaultAddress -> VaultAuthToken -> VaultConnection Authenticated

-- | Used as a type argument when constructing a 'VaultConnection'. Designates an unauthenticated connection.
data Unauthenticated

-- | Used as a type argument when constructing a 'VaultConnection'. Designates an authenticated connection.
data Authenticated

authenticatedVaultConnection :: Manager -> VaultAddress -> VaultAuthToken -> VaultConnection Authenticated
authenticatedVaultConnection = AuthenticatedVaultConnection

unauthenticatedVaultConnection :: Manager -> VaultAddress -> VaultConnection Unauthenticated
unauthenticatedVaultConnection = UnauthenticatedVaultConnection

newtype VaultAddress = VaultAddress { unVaultAddress :: Text }
    deriving (Show, Eq, Ord)

newtype VaultUnsealKey = VaultUnsealKey { unVaultUnsealKey :: Text }
    deriving (Show, Eq, Ord)

newtype VaultAuthToken = VaultAuthToken { unVaultAuthToken :: Text }
    deriving (Show, Eq, Ord)

instance FromJSON VaultAuthToken where
    parseJSON j = do
        text <- parseJSON j
        pure (VaultAuthToken text)

newtype VaultMountedPath = VaultMountedPath { unVaultMountedPath :: Text }
    deriving (Show, Eq, Ord)

newtype VaultSearchPath = VaultSearchPath { unVaultSearchPath :: Text }
    deriving (Show, Eq, Ord)

newtype VaultSecretPath = VaultSecretPath (VaultMountedPath, VaultSearchPath)
    deriving (Show, Eq, Ord)

newtype VaultAppRoleId = VaultAppRoleId { unVaultAppRoleId :: Text }
    deriving (Show, Eq, Ord)

instance FromJSON VaultAppRoleId where
    parseJSON = withObject "VaultAppRoleId" $ \v ->
        VaultAppRoleId <$> v .: "role_id"

instance ToJSON VaultAppRoleId where
    toJSON v = object [ "role_id" .= unVaultAppRoleId v ]

newtype VaultAppRoleSecretId = VaultAppRoleSecretId { unVaultAppRoleSecretId :: Text }
    deriving (Show, Eq, Ord)

instance FromJSON VaultAppRoleSecretId where
    parseJSON j = do
        text <- parseJSON j
        pure $ VaultAppRoleSecretId text

instance ToJSON VaultAppRoleSecretId where
    toJSON v = object [ "secret_id" .= unVaultAppRoleSecretId v ]

newtype VaultAppRoleSecretIdAccessor = VaultAppRoleSecretIdAccessor { unVaultAppRoleSecretIdAccessor :: Text }
    deriving (Show, Eq, Ord)

instance FromJSON VaultAppRoleSecretIdAccessor where
    parseJSON j = do
        text <- parseJSON j
        pure $ VaultAppRoleSecretIdAccessor text

instance ToJSON VaultAppRoleSecretIdAccessor where
    toJSON v = object [ "secret_id_accessor" .= unVaultAppRoleSecretIdAccessor v ]

data VaultException
    = VaultException
    | VaultException_InvalidAddress ByteString Text
    | VaultException_BadStatusCode ByteString Text BL.ByteString Int BL.ByteString
    | VaultException_ParseBodyError ByteString Text BL.ByteString Text
    deriving (Show, Eq)

instance Exception VaultException
