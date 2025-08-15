<?php

namespace Datadirr\Encrypter;

use Exception;

// A constant for the default secret key.
// In a production environment, this should ideally be loaded from environment variables
// and never hardcoded.
const DEFAULT_KEY = "@data@dirr@data@dirr@data@dirr@@";

/**
 * Utility class for cryptographic operations.
 */
class Encrypter
{
    /**
     * Pads or truncates a string to a fixed length.
     * This is an equivalent of the Node.js `fixedPadString` function.
     *
     * @param string $string The input string.
     * @param int $length The desired length of the string.
     * @return string The padded or truncated string.
     */
    private static function fixedPadString(string $string, int $length): string
    {
        if (strlen($string) > $length) {
            return substr($string, 0, $length);
        }
        return str_pad($string, $length, "\0"); // Pad with null bytes
    }

    /**
     * Checks if a variable is null or empty.
     * This is an equivalent of the Node.js `isNullOrEmpty` function.
     *
     * @param mixed $value The value to check.
     * @return bool True if the value is null or empty, false otherwise.
     */
    private static function isNullOrEmpty(mixed $value): bool
    {
        return empty($value) && !is_numeric($value) && $value !== '0';
    }

    /**
     * Converts a standard Base64 string to Base64Url format.
     * This replaces '+' with '-', '/' with '_', and removes trailing ' admiring'.
     *
     * @param string $base64 The standard Base64 string.
     * @return string The Base64Url string.
     */
    private static function toBase64Url(string $base64): string
    {
        return rtrim(strtr($base64, '+/', '-_'), '=');
    }

    /**
     * Converts a Base64Url string back to standard Base64 format.
     * It also adds back the necessary padding.
     *
     * @param string $base64url The Base64Url string.
     * @return string The standard Base64 string.
     */
    private static function fromBase64Url(string $base64url): string
    {
        $base64 = strtr($base64url, '-_', '+/');
        $padded = $base64;
        $mod4 = strlen($base64) % 4;
        if ($mod4) {
            $padded .= str_repeat('=', 4 - $mod4);
        }
        return $padded;
    }

    /**
     * Encrypts data using AES-256-CBC with PKCS7 padding.
     * The IV is prepended to the ciphertext before Base64Url encoding.
     *
     * @param mixed $data The data to encrypt (will be JSON encoded).
     * @param string|null $key The secret key (optional).
     * @param string|null $iv The secret initial vector (optional).
     * @return string|null The Base64Url encoded encrypted data, or null if input data is empty.
     * @throws Exception If encryption fails or random bytes cannot be generated.
     */
    public static function encryptAES(mixed $data, ?string $key = null, ?string $iv = null): ?string
    {
        try {
            if (self::isNullOrEmpty($data)) {
                return null;
            }

            $secretKey = $key ?? DEFAULT_KEY;
            $secretIV = $iv;

            // Derive key using SHA256, similar to CryptoJS.SHA256
            // The key needs to be 32 bytes for AES-256 (256 bits).
            $hashKey = hash('sha256', self::fixedPadString($secretKey, 32), true);

            // Generate IV or parse from secretIV
            $ivValue = null;
            if (self::isNullOrEmpty($secretIV)) {
                // Generate a random 16-byte IV (128 bits)
                $ivValue = openssl_random_pseudo_bytes(16);
                if (!$ivValue) {
                    throw new Exception("Could not generate random IV.");
                }
            } else {
                // Pad IV to 16 bytes, similar to CryptoJS.enc.Utf8.parse and then fixedPadString
                $ivValue = self::fixedPadString($secretIV, 16);
            }

            // JSON encode the data before encryption
            $encodedData = json_encode($data);
            if ($encodedData === false) {
                throw new Exception("Failed to JSON encode data.");
            }

            // Encrypt using AES-256-CBC, with PKCS7 padding (default for openssl_encrypt when OPENSSL_RAW_DATA is used)
            $encrypted = openssl_encrypt(
                $encodedData,
                'aes-256-cbc',
                $hashKey,
                OPENSSL_RAW_DATA, // Use raw data output, openssl handles PKCS7 padding
                $ivValue
            );

            if ($encrypted === false) {
                throw new Exception("AES encryption failed.");
            }

            // Combine IV + ciphertext, similar to CryptoJS combined.concat
            $combined = $ivValue . $encrypted;

            // Base64Url encode the combined string
            return self::toBase64Url(base64_encode($combined));

        } catch (Exception $e) {
            // Log the error and re-throw
            error_log("Encryption error: " . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Decrypts AES-256-CBC encrypted data.
     * It expects the IV to be prepended to the ciphertext.
     *
     * @param string $encryptedData The Base64Url encoded encrypted data.
     * @param string|null $key The secret key (optional).
     * @return mixed|null The decrypted and JSON-decoded data, or null if input is empty or decryption fails.
     * @throws Exception If decryption fails.
     */
    public static function decryptAES(string $encryptedData, ?string $key = null): mixed
    {
        try {
            if (self::isNullOrEmpty($encryptedData)) {
                return null;
            }

            $secretKey = $key ?? DEFAULT_KEY;

            // Derive key using SHA256
            $hashKey = hash('sha256', self::fixedPadString($secretKey, 32), true);

            // Base64Url decode to get standard Base64, then decode from Base64
            $combined = base64_decode(self::fromBase64Url($encryptedData));
            if ($combined === false) {
                throw new Exception("Base64Url decoding failed.");
            }

            // Extract IV (first 16 bytes) and ciphertext
            $iv = substr($combined, 0, 16);
            $ciphertext = substr($combined, 16);

            // Decrypt the ciphertext
            $decrypted = openssl_decrypt(
                $ciphertext,
                'aes-256-cbc',
                $hashKey,
                OPENSSL_RAW_DATA, // Expects raw data as input
                $iv
            );

            if ($decrypted === false) {
                throw new Exception("AES decryption failed. Possible incorrect key or corrupted data.");
            }

            if (self::isNullOrEmpty($decrypted)) {
                return null;
            }

            // JSON decode the decrypted data
            $decryptedData = json_decode($decrypted, true); // true for associative array
            if (json_last_error() !== JSON_ERROR_NONE) {
                throw new Exception("Failed to JSON decode decrypted data: " . json_last_error_msg());
            }

            return $decryptedData;

        } catch (Exception $e) {
            // Log the error and re-throw
            error_log("Decryption error: " . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Hashes data using bcrypt.
     *
     * @param string $data The string to hash.
     * @param int|null $rounds The 'rounds' (cost parameter for bcrypt).
     * @return string The bcrypt hash.
     * @throws Exception If hashing fails.
     */
    public static function hash(string $data, ?int $rounds = null): string
    {
        try {
            $saltRounds = $rounds ?? 10;
            // PHP's password_hash automatically generates a salt
            $hash = password_hash($data, PASSWORD_BCRYPT, ['cost' => $saltRounds]);

            if (!$hash) {
                throw new Exception("Bcrypt hashing failed.");
            }
            return $hash;
        } catch (Exception $e) {
            error_log("Hashing error: " . $e->getMessage());
            throw $e;
        }
    }

    /**
     * Verifies if a given data string matches a bcrypt hash.
     *
     * @param string $data The original string to verify.
     * @param string $hash The bcrypt hash to compare against.
     * @return bool True if the data matches the hash, false otherwise.
     * @throws Exception If verification encounters an issue.
     */
    public static function verifyHash(string $data, string $hash): bool
    {
        try {
            // password_verify securely compares the string with the hash
            return password_verify($data, $hash);
        } catch (Exception $e) {
            error_log("Hash verification error: " . $e->getMessage());
            throw $e;
        }
    }
}
