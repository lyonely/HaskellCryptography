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

-- Calculates the greatest common divisor of two numbers, m and n
-- Resembles Euclid's Algorithm for calculating gcd of two numbers
gcd :: Int -> Int -> Int
-- Pre: m, n >= 0
gcd m n
    | n == 0                = m
    | otherwise             = gcd n (m `mod` n)


-- Calculates the Euler phi or Totient function, which is the number of
-- integers in the range 1 to m inclusive that are relatively prime to m,
-- i.e. for which gcd (a, m) = 1
phi :: Int -> Int
-- Pre: m >= 0
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


-- Calculates (u, v, d) the gcd (d) and Bezout coefficients (u and v)
-- such that au + bv = d
computeCoeffs :: Int -> Int -> (Int, Int)
-- Pre: a, b >= 0
computeCoeffs a b
    | a == 0 && b > 0       = (0, 1)
    | b == 0                = (1, 0)
    | otherwise             = (v, (u - q * v))
    where
        (q, r) = a `quotRem` b
        (u, v) = computeCoeffs b r


-- Computes a^(-1), inverse of a modulo m, where a * a^(-1) = 1 (mod m)
inverse :: Int -> Int -> Int
-- Pre: a >= 1, m >= 2, a /= m
inverse a m
    = u `mod` m
    where
        (u, v) = computeCoeffs a m


-- Calculates (a^k mod m)
-- Computes in O(log n) time
modPow :: Int -> Int -> Int -> Int
-- Pre: a, k >= 0, m >= 1
modPow a k m
    | k == 0                = 1 `mod` m
    | k == 1                = a `mod` m
    | k `mod` 2 == 0        = modPow b j m
    | k `mod` 2 == 1        = (a * (modPow b j m)) `mod` m
    where
        j = k `div` 2
        b = a ^ 2 `mod` m


-- Returns the smallest integer that is coprime with phi
smallestCoPrimeOf :: Int -> Int
-- Pre: phi >= 0
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
-- Pre: p, q are two different prime numbers
genKeys p q
    = ((e, n), (d, n))
    where
        n = p * q
        e = smallestCoPrimeOf ((p - 1) * (q - 1))
        d = inverse e ((p - 1) * (q - 1))


-- RSA encryption/decryption
-- Returns the ciphertext x^e mod n using plain text x and public key (e, n)
rsaEncrypt :: Int -> (Int, Int) -> Int
-- Pre: x >= 1, e, n > 1, n = p*q where p and q are distinct prime numbers,
-- e is such that gcd(e, (p-1)*(q-1)) = 1
rsaEncrypt x (e, n)
    = modPow x e n


-- Returns plain text c^d mod n using ciphertext c and private key (d, n)
rsaDecrypt :: Int -> (Int, Int) -> Int
-- Pre: c >= 1, d, n > 1, n = p*q where p and q are distinct prime numbers,
-- d is such that e*d = 1 (mod (p-1)*(q-1))
rsaDecrypt c (d, n)
    = modPow c d n

-------------------------------------------------------------------------------
-- PART 2 : symmetric encryption

-- Returns position of a letter in the alphabet
toInt :: Char -> Int
-- Pre: c must be a letter
toInt c
    = ord c - ord 'a'


-- Returns the n^th letter
toChar :: Int -> Char
-- Pre: 0 <= num <= 25
toChar num
    = chr (num + ord 'a')

-- "adds" two letters
add :: Char -> Char -> Char
-- Pre: a and b are letters
add a b
    = toChar (x `mod` 26)
    where
        x = toInt a + toInt b

-- "substracts" two letters
substract :: Char -> Char -> Char
--Pre: a and b are letters
substract a b
    = toChar (y `mod` 26)
    where
        y = toInt a - toInt b

-- the next functions present
-- 2 modes of operation for block ciphers : ECB and CBC
-- based on a symmetric encryption function e/d such as "add"

-- ecb (electronic codebook) with block size of a letter
--
ecbEncrypt :: Char -> String -> String
ecbEncrypt k m
    = if null m
      then ""
      else e : ecbEncrypt k (tail m)
      where
          e = add (head m) k

ecbDecrypt :: Char -> String -> String
ecbDecrypt k c
    = if null c
      then ""
      else d : ecbDecrypt k (tail c)
      where
          d = substract (head c) k

-- cbc (cipherblock chaining) encryption with block size of a letter
-- initialisation vector iv is a letter
-- last argument is message m as a string
--
cbcEncrypt :: Char -> Char -> String -> String
cbcEncrypt k iv x
    = if null x
      then ""
      else c : cbcEncrypt k c (tail x)
      where
          c = add b k
          b = add (head x) iv

cbcDecrypt :: Char -> Char -> String -> String
cbcDecrypt k iv c
    = if null c
      then ""
      else x : cbcDecrypt k c' (tail c)
      where
          x = substract d iv
          d = substract c' k
          c' = head c
