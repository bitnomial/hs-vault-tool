{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}

-- | Unless otherwise specified, all IO functions in this module may
-- potentially throw 'HttpException' or 'VaultException'

module Network.VaultTool
    ( VaultAddress(..)
    , VaultUnsealKey(..)
    , VaultAuthToken(..)
    , VaultAppRoleId(..)
    , VaultAppRoleSecretId(..)
    , VaultException(..)

    , VaultConnection
    , Unauthenticated
    , Authenticated
    , defaultManager
    , authenticatedVaultConnection
    , unauthenticatedVaultConnection

    , VaultHealth(..)
    , vaultHealth

    , connectToVaultAppRole

    , vaultAuthEnable

    , vaultPolicyCreate

    , vaultInit
    , VaultSealStatus(..)
    , vaultSealStatus
    , vaultSeal
    , VaultUnseal(..)
    , vaultUnseal

    , vaultAppRoleCreate
    , vaultAppRoleRoleIdRead
    , vaultAppRoleSecretIdGenerate
    , defaultVaultAppRoleParameters
    , VaultAppRoleParameters(..)
    , VaultAppRoleSecretIdGenerateResponse(..)

    , VaultMount(..)
    , VaultMountRead
    , VaultMountWrite
    , VaultMountConfig(..)
    , VaultMountConfigRead
    , VaultMountConfigWrite
    , VaultMountOptions(..)
    , VaultMountConfigOptions
    , vaultMounts
    , vaultMountTune
    , vaultMountSetTune
    , vaultNewMount
    , vaultUnmount

    , VaultMountedPath(..)
    , VaultSearchPath(..)
    , VaultSecretPath(..)
    ) where
import Control.Exception (throwIO)
import Data.Aeson
import Data.Aeson.Types (parseEither, Pair)
import Data.List (sortOn)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Maybe (catMaybes)
import Network.HTTP.Client (Manager, newManager)
import Network.HTTP.Client.TLS (tlsManagerSettings)
import qualified Data.HashMap.Strict as H
import Text.Read (readEither)

import Network.VaultTool.Internal
import Network.VaultTool.Types

-- | <https://www.vaultproject.io/docs/http/sys-health.html>
--
-- See 'vaultHealth'
data VaultHealth = VaultHealth
    { _VaultHealth_Version :: Text
    , _VaultHealth_ServerTimeUtc :: Int
    , _VaultHealth_Initialized :: Bool
    , _VaultHealth_Sealed :: Bool
    , _VaultHealth_Standby :: Bool
    }
    deriving (Show, Eq, Ord)

instance FromJSON VaultHealth where
    parseJSON = withObject "VaultHealth" $ \v ->
        VaultHealth <$>
             v .: "version" <*>
             v .: "server_time_utc" <*>
             v .: "initialized" <*>
             v .: "sealed" <*>
             v .: "standby"

-- | https://www.vaultproject.io/docs/http/sys-health.html
vaultHealth :: VaultConnection a -> IO VaultHealth
vaultHealth conn = do
    runVaultRequestUnauthenticated conn
        . withStatusCodes [200, 429, 501, 503]
        $ newGetRequest "/sys/health"

defaultManager :: IO Manager
defaultManager = newManager tlsManagerSettings

-- | Initializes the 'VaultConnection' objects using approle credentials to retrieve an authtoken,
-- and then calls `connectToVault`
connectToVaultAppRole :: Manager -> VaultAddress -> VaultAppRoleId -> VaultAppRoleSecretId -> IO (VaultConnection Authenticated)
connectToVaultAppRole manager addr roleId secretId =
    authenticatedVaultConnection manager addr <$>
        vaultAppRoleLogin (unauthenticatedVaultConnection manager addr) roleId secretId

-- | <https://www.vaultproject.io/docs/http/sys-init.html>
--
-- See 'vaultInit'
data VaultInitResponse = VaultInitResponse
    { _VaultInitResponse_Keys :: [Text]
    , _VaultInitResponse_RootToken :: VaultAuthToken
    }
    deriving (Show, Eq, Ord)

instance FromJSON VaultInitResponse where
    parseJSON = withObject "VaultInitResponse" $ \v ->
        VaultInitResponse <$>
             v .: "keys" <*>
             v .: "root_token"

-- | <https://www.vaultproject.io/docs/http/sys-init.html>
vaultInit
    :: VaultConnection a
    -> Int -- ^ @secret_shares@: The number of shares to split the master key
           -- into
    -> Int -- ^ @secret_threshold@: The number of shares required to
           -- reconstruct the master key. This must be less than or equal to
           -- secret_shares
    -> IO ([VaultUnsealKey], VaultAuthToken) -- ^ master keys and initial root token
vaultInit conn secretShares secretThreshold = do
    let reqBody = object
            [ "secret_shares" .= secretShares
            , "secret_threshold" .= secretThreshold
            ]
    rsp <- runVaultRequestUnauthenticated conn $
        newPutRequest "/sys/init" (Just reqBody)
    let VaultInitResponse{_VaultInitResponse_Keys, _VaultInitResponse_RootToken} = rsp
    pure (map VaultUnsealKey _VaultInitResponse_Keys, _VaultInitResponse_RootToken)

-- | <https://www.vaultproject.io/docs/http/sys-seal-status.html>
--
-- See 'vaultSealStatus'
data VaultSealStatus = VaultSealStatus
    { _VaultSealStatus_Sealed :: Bool
    , _VaultSealStatus_T :: Int -- ^ threshold
    , _VaultSealStatus_N :: Int -- ^ number of shares
    , _VaultSealStatus_Progress :: Int
    }
    deriving (Show, Eq, Ord)

instance FromJSON VaultSealStatus where
    parseJSON = withObject "VaultSealStatus" $ \v ->
        VaultSealStatus <$>
             v .: "sealed" <*>
             v .: "t" <*>
             v .: "n" <*>
             v .: "progress"

vaultSealStatus :: VaultConnection a -> IO VaultSealStatus
vaultSealStatus conn = runVaultRequestUnauthenticated conn (newGetRequest "/sys/seal-status")

-- | <https://www.vaultproject.io/api/auth/approle/index.html>
--
-- See 'sample-response-7'
data VaultAuth = VaultAuth
    { _VaultAuth_Renewable :: Bool
    , _VaultAuth_LeaseDuration :: Int
    , _VaultAuth_Policies :: [Text]
    , _VaultAuth_ClientToken :: VaultAuthToken
    }
    deriving (Show, Eq, Ord)

instance FromJSON VaultAuth where
    parseJSON = withObject "VaultAuth" $ \v ->
        VaultAuth <$>
            v .: "renewable" <*>
            v .: "lease_duration" <*>
            v .: "policies" <*>
            v .: "client_token"

-- | <https://www.vaultproject.io/api/auth/approle/index.html>
--
-- See 'sample-response-7'
data VaultAppRoleResponse = VaultAppRoleResponse
    { _VaultAppRoleResponse_Auth :: Maybe VaultAuth
    , _VaultAppRoleResponse_Warnings :: Value
    , _VaultAppRoleResponse_WrapInfo :: Value
    , _VaultAppRoleResponse_Data :: Value
    , _VaultAppRoleResponse_LeaseDuration :: Int
    , _VaultAppRoleResponse_Renewable :: Bool
    , _VaultAppRoleResponse_LeaseId :: Text
    }
    deriving (Show, Eq)

instance FromJSON VaultAppRoleResponse where
    parseJSON = withObject "VaultAppRoleResponse" $ \v ->
        VaultAppRoleResponse <$>
            v .:? "auth" <*>
            v .: "warnings" <*>
            v .: "wrap_info" <*>
            v .: "data" <*>
            v .: "lease_duration" <*>
            v .: "renewable" <*>
            v .: "lease_id"

-- | <https://www.vaultproject.io/docs/auth/approle.html>
vaultAppRoleLogin :: VaultConnection a -> VaultAppRoleId -> VaultAppRoleSecretId -> IO VaultAuthToken
vaultAppRoleLogin conn roleId secretId = do
    response <-
        runVaultRequestUnauthenticated
            conn
            (newPostRequest "/auth/approle/login" $ Just reqBody)
    maybe failOnNullAuth (return . _VaultAuth_ClientToken) $ _VaultAppRoleResponse_Auth response
  where
  reqBody = object
      [ "role_id" .= unVaultAppRoleId roleId,
        "secret_id" .= unVaultAppRoleSecretId secretId
      ]
  failOnNullAuth = fail "Auth on login is null"

-- | <https://www.vaultproject.io/docs/auth/approle.html#via-the-api-1>
vaultAuthEnable :: VaultConnection Authenticated-> Text -> IO ()
vaultAuthEnable conn authMethod =
    runVaultRequestAuthenticated_ conn
        . withStatusCodes [200, 204]
        $ newPostRequest ("/sys/auth/" <> authMethod) (Just reqBody)
  where
  reqBody = object [ "type" .= authMethod ]

-- | <https://www.vaultproject.io/api/system/policies.html#create-update-acl-policy>
vaultPolicyCreate :: VaultConnection Authenticated -> Text -> Text -> IO ()
vaultPolicyCreate conn policyName policy =
    runVaultRequestAuthenticated_ conn
        . withStatusCodes [200, 204]
        $ newPutRequest
            ("/sys/policies/acl/" <> policyName)
            (Just reqBody)
    where
    reqBody = object [ "policy" .= policy ]

newtype VaultAppRoleListResponse = VaultAppRoleListResponse
    { _VaultAppRoleListResponse_AppRoles :: [Text] }

instance FromJSON VaultAppRoleListResponse where
    parseJSON = withObject "VaultAppRoleListResponse" $ \v ->
        VaultAppRoleListResponse <$>
            v .: "keys"

-- | <https://www.vaultproject.io/api/auth/approle/index.html#create-new-approle>
--
-- Note: For TTL fields, only integer number seconds, i.e. 3600, are supported
data VaultAppRoleParameters = VaultAppRoleParameters
    { _VaultAppRoleParameters_BindSecretId :: Bool
    , _VaultAppRoleParameters_Policies :: [Text]
    , _VaultAppRoleParameters_SecretIdNumUses :: Maybe Int
    , _VaultAppRoleParameters_SecretIdTTL :: Maybe Int
    , _VaultAppRoleParameters_TokenNumUses :: Maybe Int
    , _VaultAppRoleParameters_TokenTTL :: Maybe Int
    , _VaultAppRoleParameters_TokenMaxTTL :: Maybe Int
    , _VaultAppRoleParameters_Period :: Maybe Int
    }

instance ToJSON VaultAppRoleParameters where
    toJSON v = object $
        [ "bind_secret_id" .= _VaultAppRoleParameters_BindSecretId v
        , "policies" .= _VaultAppRoleParameters_Policies v
        ] <> catMaybes
        [ "secret_id_num_uses" .=? _VaultAppRoleParameters_SecretIdNumUses v
        , "secret_id_ttl" .=? _VaultAppRoleParameters_SecretIdTTL v
        , "token_num_uses" .=? _VaultAppRoleParameters_TokenNumUses v
        , "token_ttl" .=? _VaultAppRoleParameters_TokenTTL v
        , "token_max_ttl" .=? _VaultAppRoleParameters_TokenMaxTTL v
        , "period" .=? _VaultAppRoleParameters_Period v
        ]
      where
        (.=?) :: ToJSON x => Text -> Maybe x -> Maybe Pair
        t .=? x = (t .=) <$> x

instance FromJSON VaultAppRoleParameters where
    parseJSON = withObject "VaultAppRoleParameters" $ \v ->
        VaultAppRoleParameters <$>
            v .: "bind_secret_id" <*>
            v .: "policies" <*>
            v .:? "secret_id_num_uses" <*>
            v .:? "secret_id_ttl" <*>
            v .:? "token_num_uses" <*>
            v .:? "token_ttl" <*>
            v .:? "token_max_ttl" <*>
            v .:? "period"

defaultVaultAppRoleParameters :: VaultAppRoleParameters
defaultVaultAppRoleParameters = VaultAppRoleParameters True [] Nothing Nothing Nothing Nothing Nothing Nothing

-- | <https://www.vaultproject.io/api/auth/approle/index.html#create-new-approle>
vaultAppRoleCreate :: VaultConnection Authenticated -> Text -> VaultAppRoleParameters -> IO ()
vaultAppRoleCreate conn appRoleName varp =
    runVaultRequestAuthenticated_ conn
    . withStatusCodes [200, 204]
    $ newPostRequest ("/auth/approle/role/" <> appRoleName) (Just varp)

-- | <https://www.vaultproject.io/api/auth/approle/index.html#read-approle-role-id>
vaultAppRoleRoleIdRead :: VaultConnection Authenticated -> Text -> IO VaultAppRoleId
vaultAppRoleRoleIdRead conn appRoleName = do
    response <- runVaultRequestAuthenticated conn $ newGetRequest ("/auth/approle/role/" <> appRoleName <> "/role-id")
    let d = _VaultAppRoleResponse_Data response
    case parseEither parseJSON d of
      Left err -> throwIO $ VaultException_ParseBodyError "GET" ("/auth/approle/role/" <> appRoleName <> "/role-id") (encode d) (T.pack err)
      Right obj -> return obj

data VaultAppRoleSecretIdGenerateResponse = VaultAppRoleSecretIdGenerateResponse
    { _VaultAppRoleSecretIdGenerateResponse_SecretIdAccessor :: VaultAppRoleSecretIdAccessor
    , _VaultAppRoleSecretIdGenerateResponse_SecretId :: VaultAppRoleSecretId
    }

instance FromJSON VaultAppRoleSecretIdGenerateResponse where
    parseJSON = withObject "VaultAppRoleSecretIdGenerateResponse" $ \v ->
        VaultAppRoleSecretIdGenerateResponse <$>
            v .: "secret_id_accessor" <*>
            v .: "secret_id"

-- | <https://www.vaultproject.io/api/auth/approle/index.html#generate-new-secret-id>
vaultAppRoleSecretIdGenerate :: VaultConnection Authenticated -> Text -> Text -> IO VaultAppRoleSecretIdGenerateResponse
vaultAppRoleSecretIdGenerate conn appRoleName metadata = do
    response <- runVaultRequestAuthenticated conn $ newPostRequest ("/auth/approle/role/" <> appRoleName <> "/secret-id") (Just reqBody)
    let d = _VaultAppRoleResponse_Data response
    case parseEither parseJSON d of
      Left err -> throwIO $ VaultException_ParseBodyError "POST" ("/auth/approle/role/" <> appRoleName <> "/secret-id") (encode d) (T.pack err)
      Right obj -> return obj
    where
    reqBody = object[ "metadata" .= metadata ]

vaultSeal :: VaultConnection Authenticated -> IO ()
vaultSeal conn =
    runVaultRequestAuthenticated_ conn
        . withStatusCodes [200, 204]
        $ newPutRequest "/sys/seal" (Nothing :: Maybe ())

-- | <https://www.vaultproject.io/docs/http/sys-unseal.html>
--
-- See 'vaultUnseal'
data VaultUnseal
    = VaultUnseal_Key VaultUnsealKey
    | VaultUnseal_Reset
    deriving (Show, Eq, Ord)

-- | <https://www.vaultproject.io/docs/http/sys-unseal.html>
vaultUnseal :: VaultConnection a -> VaultUnseal -> IO VaultSealStatus
vaultUnseal conn unseal = do
    let reqBody = case unseal of
            VaultUnseal_Key (VaultUnsealKey key) -> object
                [ "key" .= key
                ]
            VaultUnseal_Reset -> object
                [ "reset" .= True
                ]
    runVaultRequestUnauthenticated conn $ newPutRequest "/sys/unseal" (Just reqBody)

type VaultMountRead = VaultMount Text VaultMountConfigRead (Maybe VaultMountConfigOptions)
type VaultMountWrite = VaultMount (Maybe Text) (Maybe VaultMountConfigWrite) (Maybe VaultMountConfigOptions)
type VaultMountConfigRead = VaultMountConfig Int
type VaultMountConfigWrite = VaultMountConfig (Maybe Int)
type VaultMountConfigOptions = VaultMountOptions (Maybe Int)

-- | <https://www.vaultproject.io/docs/http/sys-mounts.html>
data VaultMount a b c = VaultMount
    { _VaultMount_Type :: Text
    , _VaultMount_Description :: a
    , _VaultMount_Config :: b
    , _VaultMount_Options :: c
    }
    deriving (Show, Eq, Ord)

instance FromJSON VaultMountRead where
    parseJSON = withObject "VaultMountRead" $ \v ->
        VaultMount <$>
             v .: "type" <*>
             v .: "description" <*>
             v .: "config" <*>
             v .: "options"

instance ToJSON VaultMountWrite where
    toJSON v = object
        [ "type" .= _VaultMount_Type v
        , "description" .= _VaultMount_Description v
        , "config" .= _VaultMount_Config v
        , "options" .= _VaultMount_Options v
        ]

-- | <https://www.vaultproject.io/docs/http/sys-mounts.html>
data VaultMountConfig a = VaultMountConfig
    { _VaultMountConfig_DefaultLeaseTtl :: a
    , _VaultMountConfig_MaxLeaseTtl :: a
    }
    deriving (Show, Eq, Ord)

instance FromJSON VaultMountConfigRead where
    parseJSON = withObject "VaultMountConfigRead" $ \v ->
        VaultMountConfig <$>
             v .: "default_lease_ttl" <*>
             v .: "max_lease_ttl"

instance ToJSON VaultMountConfigWrite where
    toJSON v = object
        [ "default_lease_ttl" .= fmap formatSeconds (_VaultMountConfig_DefaultLeaseTtl v)
        , "max_lease_ttl" .= fmap formatSeconds (_VaultMountConfig_MaxLeaseTtl v)
        ]

formatSeconds :: Int -> String
formatSeconds n = show n ++ "s"

newtype VaultMountOptions a = VaultMountOptions
    { _VaultMountOptions_Version :: a
    }
    deriving (Show, Eq, Ord)

instance FromJSON VaultMountConfigOptions where
    parseJSON = withObject "VaultMountConfigOptions" $ \v ->
        VaultMountOptions <$> (either fail pure . readEither <$> v .: "version")

instance ToJSON VaultMountConfigOptions where
    toJSON v =
        object
            [ "version" .= (show <$> _VaultMountOptions_Version v)
            ]

-- | <https://www.vaultproject.io/docs/http/sys-mounts.html>
--
-- For your convenience, the results are returned sorted (by the mount point)
vaultMounts :: VaultConnection Authenticated -> IO [(Text, VaultMountRead)]
vaultMounts conn = do
    let reqPath = "/sys/mounts"
    rspObj <- runVaultRequestAuthenticated conn $ newGetRequest reqPath

    -- Vault 0.6.1 has a different format than previous versions.
    -- See <https://github.com/hashicorp/vault/issues/1965>
    --
    -- We do some detection to support both the new and the old format:
    let root = case H.lookup "data" rspObj of
            Nothing -> Object rspObj
            Just v -> v

    case parseEither parseJSON root of
        Left err -> throwIO $ VaultException_ParseBodyError "GET" reqPath (encode rspObj) (T.pack err)
        Right obj -> pure $ sortOn fst (H.toList obj)

-- | <https://www.vaultproject.io/docs/http/sys-mounts.html>
vaultMountTune :: VaultConnection Authenticated -> Text -> IO VaultMountConfigRead
vaultMountTune conn mountPoint =
    runVaultRequestAuthenticated conn
        . newGetRequest
        $ "/sys/mounts/" <> mountPoint <> "/tune"

-- | <https://www.vaultproject.io/docs/http/sys-mounts.html>
vaultMountSetTune :: VaultConnection Authenticated -> Text -> VaultMountConfigWrite -> IO ()
vaultMountSetTune conn mountPoint mountConfig =
    runVaultRequestAuthenticated_ conn
        . withStatusCodes [200, 204]
        $ newPostRequest ("/sys/mounts/" <> mountPoint <> "/tune") (Just mountConfig)

-- | <https://www.vaultproject.io/docs/http/sys-mounts.html>
vaultNewMount :: VaultConnection Authenticated -> Text -> VaultMountWrite -> IO ()
vaultNewMount conn mountPoint vaultMount =
    runVaultRequestAuthenticated_ conn
        . withStatusCodes [200, 204]
        $ newPostRequest ("/sys/mounts/" <> mountPoint) (Just vaultMount)

-- | <https://www.vaultproject.io/docs/http/sys-mounts.html>
vaultUnmount :: VaultConnection Authenticated -> Text -> IO ()
vaultUnmount conn mountPoint =
    runVaultRequestAuthenticated_ conn
        . withStatusCodes [200, 204]
        . newDeleteRequest
        $ "/sys/mounts/" <> mountPoint

data VaultSecretMetadata = VaultSecretMetadata
    { _VaultSecretMetadata_leaseDuration :: Int
    , _VaultSecretMetadata_leaseId :: Text
    , _VauleSecretMetadata_renewable :: Bool
    }
    deriving (Show, Eq {- TODO Ord -})

instance FromJSON VaultSecretMetadata where
    parseJSON = withObject "VaultSecretMetadata" $ \v ->
        VaultSecretMetadata <$>
            v .: "lease_duration" <*>
            v .: "lease_id" <*>
            v .: "renewable"
