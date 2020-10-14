module Crypto where

import Data.Char

import Prelude hiding (gcd)

{-
The advantage of symmetric encryption schemes like AES is that they are efficient
and we can encrypt data of arbitrary size. The problem is how to share the key.
The flaw of the RSA is that it is slow and we can only encrypt data of size lower
than the RSA modulus n, usually around 1024 bits (64 bits for this exercise!).

We usually encrypt messages with a private encryption scheme like AES-256 with
a symmetric key k. The key k of fixed size 256 bits for example is then exchanged
via the aymmetric RSA.
-}

-------------------------------------------------------------------------------
-- PART 1 : asymmetric encryption

gcd :: Int -> Int -> Int
gcd m n
    | n == 0        = m
    | otherwise     = gcd n (m `mod` n)

phi :: Int -> Int
--Pre: m >= 1
phi m
    | m == 1 || m == 0      = m
    | otherwise             = phi' m x
    where
        x = 1
        phi' :: Int -> Int -> Int
        phi' a b
            | a == b            = 0
            | gcd a b ==  1     = 1 + phi' a (b + 1)
            | otherwise         = phi' a (b + 1)



--length [x | x <- [1..m], gcd m x == 1]

-- Calculates (u, v, d) the gcd (d) and Bezout coefficients (u and v)
-- such that au + bv = d
computeCoeffs :: Int -> Int -> (Int, Int)
computeCoeffs a b
    | a == 0 && b > 0   = (0,1)
    | b == 0            = (1,0)
    | otherwise         = (v , (u - q * v))
    where
        (q , r) = a `quotRem` b
        (u , v) = computeCoeffs b r


-- Inverse of a modulo m
inverse :: Int -> Int -> Int
inverse a m
    = u `mod` m
    where (u , v) = computeCoeffs a m

-- Calculates (a^k mod m)
modPow :: Int -> Int -> Int -> Int
modPow a k m
    | k == 0            = 1 `mod` m
    | k == 1            = a `mod` m
    | k `mod` 2 == 0    = modPow b j m
    | k `mod` 2 == 1    = (a * (modPow b j m)) `mod` m
    where
        j = k `div` 2
        b = a ^ 2 `mod` m

-- Returns the smallest integer that is coprime with phi
smallestCoPrimeOf :: Int -> Int
smallestCoPrimeOf phi
    = smallestCoPrimeOf' phi n
    where
        n = 2
        smallestCoPrimeOf' :: Int -> Int -> Int
        smallestCoPrimeOf' x y
            | gcd x y == 1      = y
            | otherwise         = smallestCoPrimeOf' x (y + 1)



-- Generates keys pairs (public, private) = ((e, n), (d, n))
-- given two "large" distinct primes, p and q
genKeys :: Int -> Int -> ((Int, Int), (Int, Int))
genKeys p q
    = ((e , n), (d , n))
  where
      n = p * q
      e = smallestCoPrimeOf ((p - 1) * (q - 1))
      d = inverse e ((p - 1) * (q - 1))

-- RSA encryption/decryption
rsaEncrypt :: Int -> (Int, Int) -> Int
rsaEncrypt x (e , n)
  = modPow x e n

rsaDecrypt :: Int -> (Int, Int) -> Int
rsaDecrypt c (d , n)
  = modPow c d n

-------------------------------------------------------------------------------
-- PART 2 : symmetric encryption

-- Returns position of a letter in the alphabet
toInt :: Char -> Int
toInt
  = undefined

-- Returns the n^th letter
toChar :: Int -> Char
toChar
  = undefined

-- "adds" two letters
add :: Char -> Char -> Char
add
  = undefined

-- "substracts" two letters
substract :: Char -> Char -> Char
substract
  = undefined

-- the next functions present
-- 2 modes of operation for block ciphers : ECB and CBC
-- based on a symmetric encryption function e/d such as "add"

-- ecb (electronic codebook) with block size of a letter
--
ecbEncrypt :: Char -> String -> String
ecbEncrypt
  = undefined

ecbDecrypt :: Char -> String -> String
ecbDecrypt
  = undefined

-- cbc (cipherblock chaining) encryption with block size of a letter
-- initialisation vector iv is a letter
-- last argument is message m as a string
--
cbcEncrypt :: Char -> Char -> String -> String
cbcEncrypt
  = undefined

cbcDecrypt :: Char -> Char -> String -> String
cbcDecrypt
  = undefined
