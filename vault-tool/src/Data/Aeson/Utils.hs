{-# LANGUAGE OverloadedStrings #-}

module Data.Aeson.Utils (
    object,
    (.=!),
    (.=?),
    DataWrapper (..),
) where

import Data.Aeson (FromJSON, Key, KeyValue, ToJSON, Value, withObject, (.:), (.=))
import qualified Data.Aeson as Aeson
import Data.Aeson.Types (Pair)
import Data.Maybe (catMaybes)

object :: [Maybe Pair] -> Value
object = Aeson.object . catMaybes

(.=!) :: (KeyValue a, ToJSON b) => Key -> b -> Maybe a
k .=! v = Just $ k .= v

(.=?) :: (Functor f, KeyValue a, ToJSON b) => Key -> f b -> f a
k .=? v = (k .=) <$> v

newtype DataWrapper a = DataWrapper {unDataWrapper :: a}

instance ToJSON a => ToJSON (DataWrapper a) where
    toJSON (DataWrapper x) = object ["data" .=! x]

instance FromJSON a => FromJSON (DataWrapper a) where
    parseJSON = withObject "DataWrapper" $ fmap DataWrapper . (.: "data")
