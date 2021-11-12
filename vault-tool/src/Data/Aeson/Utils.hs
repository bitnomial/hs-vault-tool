{-# LANGUAGE OverloadedStrings #-}
module Data.Aeson.Utils (
    object,
    (.=!),
    (.=?),
    DataWrapper (..)
) where

import Data.Aeson (FromJSON, KeyValue, ToJSON, Value, (.=), (.:), withObject)
import qualified Data.Aeson as Aeson
import Data.Maybe (catMaybes)
import Data.Text (Text)

object :: [Maybe (Text, Value)] -> Value
object = Aeson.object . catMaybes

(.=!) :: (KeyValue a, ToJSON b) => Text -> b -> Maybe a
k .=! v = Just $ k .= v

(.=?) :: (Functor f, KeyValue a, ToJSON b) => Text -> f b -> f a
k .=? v = (k .=) <$> v

newtype DataWrapper a = DataWrapper { unDataWrapper :: a }

instance ToJSON a => ToJSON (DataWrapper a) where
    toJSON (DataWrapper x) = object ["data" .=! x]

instance FromJSON a => FromJSON (DataWrapper a) where
    parseJSON = withObject "DataWrapper" $ fmap DataWrapper . (.: "data")
