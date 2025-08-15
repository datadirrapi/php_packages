<?php

namespace Datadirr\Tokenizer;

use Encrypter;
use Exception;

/**
 * Utility class for generating and verifying application tokens.
 * These tokens are essentially encrypted payloads with expiration times.
 */
class Tokenizer
{
    /**
     * Helper function to check if a value is null or empty.
     * Replicated from Encrypter for self-containment, but can be moved to a shared utility.
     *
     * @param mixed $value The value to check.
     * @return bool True if the value is null or empty, false otherwise.
     */
    private static function isNullOrEmpty(mixed $value): bool
    {
        return empty($value) && !is_numeric($value) && $value !== '0';
    }

    /**
     * Generates an encrypted token with an optional expiration time.
     * The token payload includes 'issued at' (iat), 'expires at' (exp), and the original payload.
     *
     * @param mixed $payload The data to be stored in the token.
     * @param int|null $seconds Token expiry seconds, 0|null for No Expire (optional).
     * @param string|null $key The secret key (optional).
     * @return string|null The encrypted token (Base64Url encoded), or null on failure.
     * @throws Exception If encryption fails.
     */
    public static function generateToken(mixed $payload, ?int $seconds = null, ?string $key = null): ?string
    {
        try {
            $iat = time(); // Current Unix timestamp (issued at)
            $exp = null; // Expiration at timestamp

            if (!self::isNullOrEmpty($seconds)) {
                $exp = $iat + $seconds; // Calculate expiration timestamp
            }

            $tokenPayload = [
                'iat' => $iat,
                'exp' => $exp,
                'payload' => $payload, // The original data
            ];

            // Use Encrypted to encrypt the token payload
            return Encrypter::encryptAES($tokenPayload, $key);

        } catch (Exception $e) {
            // Log the error and return null as per Node.js behavior
            error_log("Token generation error: " . $e->getMessage());
            return null;
        }
    }

    /**
     * Verifies an encrypted token and checks its expiration status.
     *
     * @param string $token The encrypted token string.
     * @param string|null $key The secret key (optional).
     * @return array An array containing 'valid' (bool), 'message' (string), and 'payload' (mixed).
     * @throws Exception If decryption fails, though caught internally.
     */
    public static function verifyToken(string $token, ?string $key = null): array
    {
        try {
            if (self::isNullOrEmpty($token)) {
                return ['valid' => false, 'message' => "Invalid token (empty)", 'payload' => null];
            }

            // Decrypt the token using Encrypter
            $tokenPayload = Encrypter::decryptAES($token, $key);

            if (self::isNullOrEmpty($tokenPayload)) {
                return ['valid' => false, 'message' => "Invalid token (decryption failed)", 'payload' => null];
            }

            // Check if 'exp' (expiration at) exists and is not null
            if (isset($tokenPayload['exp']) && !self::isNullOrEmpty($tokenPayload['exp'])) {
                try {
                    $expirationTimestamp = (int)$tokenPayload['exp']; // Ensure it's an integer
                    $currentTimestamp = time(); // Get current Unix timestamp

                    if ($expirationTimestamp < $currentTimestamp) {
                        return ['valid' => false, 'message' => "Token expired", 'payload' => null];
                    }
                } catch (Exception $e) {
                    // Handle invalid date format in token payload
                    error_log("Invalid 'exp' format in token payload: " . $e->getMessage());
                    return ['valid' => false, 'message' => "Invalid token (corrupted expiration data)", 'payload' => null];
                }
            }

            // If we reached here, the token is valid (either no expiration or not expired)
            return ['valid' => true, 'message' => "Valid token", 'payload' => $tokenPayload['payload']];

        } catch (Exception $e) {
            // Catch any general decryption or parsing errors
            error_log("Token verification error: " . $e->getMessage());
            return ['valid' => false, 'message' => "Invalid token (processing error)", 'payload' => null];
        }
    }

    /**
     * Checks if a token is expired.
     *
     * @param string $token The encrypted token string.
     * @param string|null $key The secret key (optional).
     * @return bool True if the token is expired or invalid, false otherwise.
     */
    public static function isTokenExpired(string $token, ?string $key = null): bool
    {
        try {
            $data = self::verifyToken($token, $key);
            return !$data['valid'];
        } catch (Exception $e) {
            // Should theoretically be caught by verifyToken, but as a safeguard
            error_log("isTokenExpired error: " . $e->getMessage());
            return true; // Assume expired/invalid on error
        }
    }
}