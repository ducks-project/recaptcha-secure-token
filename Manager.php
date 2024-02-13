<?php

namespace Ducks\Component\RecaptchaSecureToken;

class Manager implements ManagerInterface
{
    protected string $key;
    protected string $secret;

    public function __construct($config = [])
    {
        $this->key = $config['site_key'] ?? '';
        $this->secret = $config['site_secret'] ?? '';
    }

    public function getSiteKey(): string
    {
        return $this->key;
    }

    public function setSiteKey(string $key): self
    {
        $this->key = $key;

        return $this;
    }

    public function setSiteSecret(string $secret): self
    {
        $this->secret = $secret;

        return $this;
    }

    /**
     * encode() alias.
     */
    public function secureToken(string $session_id, ?float $timestamp = null): string
    {
        return $this->encode($session_id, $timestamp);
    }

    /**
     * decode() alias.
     */
    public function decodeSecureToken(string $token): array
    {
        return $this->decode($token);
    }

    /**
     * Create an encrypted secure token for the given session id.
     *
     * @param string $session_id a unique session identifier.
     * @param float|null $timestamp in milliseconds, defaults to current time.
     *
     * @return string Recaptcha-compatible base64 encoded encrypted binary data.
     */
    public function encode(string $session_id, ?float $timestamp = null): string
    {
        $plaintext = \json_encode([
            'session_id' => $session_id,
            'ts_ms' => $timestamp ??= $this->currentTimestamp(),
        ]);

        $encrypted = $this->encryptData($plaintext);

        return $this->base64Encode($encrypted);
    }

    /**
     * Decode and decrypt a secure token generated using this algorithm.
     *
     * @param string $secure_token base64 encoded secure token
     *
     * @return array includes the keys 'session_id' and 'ts_ms'
     */
    public function decode(string $token): array
    {
        $binary = $this->base64Decode($token);
        $decrypted = $this->decryptData($binary);

        return \json_decode($decrypted);
    }

    /**
     * Encrypt an arbitrary string using the site secret.
     *
     * @param string $plaintext
     *
     * @return string binary data
     *
     * @throws \BadMethodCallException if no secret
     * @throws \LengthException
     * @throws \UnexpectedValueException
     */
    public function encryptData(string $plaintext): string
    {
        return $this->encryptAes(
            $this->pad($plaintext, 16),
            $this->secretKey()
        );
    }

    /**
     * Decrypt the given data using the site secret.
     *
     * @param string $encrypted binary data
     *
     * @return string plaintext string
     *
     * @throws \BadMethodCallException if no secret
     * @throws \LengthException
     * @throws \UnexpectedValueException
     */
    public function decryptData(string $encrypted)
    {
        $padded = $this->decryptAes($encrypted, $this->secretKey());

        return $this->stripPadding($padded);
    }

    /**
     * Get the current timestamp in milliseconds.
     *
     * @return float
     */
    protected function currentTimestamp(): float
    {
        return \round(\microtime(true) * 1000);
    }

    /**
     * Returns the site secret in the key format required for encryption.
     *
     * @return string
     *
     * @throws \BadMethodCallException if no secret
     */
    protected function secretKey(): string
    {
        if (!isset($this->secret)) {
            throw new \BadMethodCallException("Missing site_secret");
        }

        $hash = \hash('sha1', $this->secret, true);
        return \substr($hash, 0, 16);
    }

    /**
     * Encrypts the given input string using the provided key.
     *
     * Note that the algorithm, block mode, and key format
     * are defined by ReCaptcha code linked below.
     *
     * @see https://github.com/google/recaptcha-java/blob/master/appengine/src/main/java/com/google/recaptcha/STokenUtils.java
     *
     * @param $input
     * @param $secret
     *
     * @return string
     *
     * @throws \LengthException
     * @throws \UnexpectedValueException
     */
    protected function encryptAes(string $input, string $secret): string
    {
        if (\in_array(static::CYPHER, \openssl_get_cipher_methods())) {
            // $ivlen = \openssl_cipher_iv_length(static::CYPHER);
            $iv = ''; // \openssl_random_pseudo_bytes($ivlen);
            $result = \openssl_encrypt(
                $input,
                static::CYPHER,
                $secret,
                OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
                $iv
            );

            if (false === $result) {
                throw new \LengthException('Error during encryption');
            }

            return $result;
        }

        throw new \UnexpectedValueException('Bad encryption');
    }

    /**
     * @param $input
     * @param $secret
     *
     * @return string
     *
     * @throws \LengthException
     * @throws \UnexpectedValueException
     */
    protected function decryptAes(string $input, string $secret): string
    {
        if (\in_array(static::CYPHER, \openssl_get_cipher_methods())) {
            // $ivlen = openssl_cipher_iv_length(static::CYPHER);
            $iv = ''; // \substr($input, 0, $ivlen);
            $result = openssl_decrypt(
                $input,
                static::CYPHER,
                $secret,
                OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
                $iv
            );

            if (false === $result) {
                throw new \LengthException('Error during encryption');
            }

            return $result;
        }

        throw new \UnexpectedValueException('Bad encryption');
    }

    /**
     * Pad the input string to a multiple of {$block_size}. The
     * padding algorithm is defined in the PKCS#5 and PKCS#7 standards
     * (which differ only in block size). See RFC 5652 Sec 6.3 for
     * implementation details.
     *
     * NB: the Java implementation of the ReCaptcha encryption algorithm
     * uses a block size of 16, despite being named PKCS#5. This is
     * consistent with the AES 128-bit cipher.
     *
     * @param string $input
     * @param int $block_size
     *
     * @return string
     */
    protected function pad(string $input, int $block_size = 16): string
    {
        $pad = $block_size - (\strlen($input) % $block_size);
        return $input . \str_repeat(\chr($pad), $pad);
    }

    /**
     * Naively strip padding from an input string.
     *
     * @param string $input padded input string.
     *
     * @return string
     */
    protected function stripPadding($input)
    {
        $padding_length = \ord(\substr($input, -1));
        return \substr($input, 0, \strlen($input) - $padding_length);
    }

    /**
     * Generate an "URL-safe" base64 encoded string from the
     * given input data.
     *
     * @param string $input
     *
     * @return string
     */
    protected function base64Encode($input)
    {
        return \str_replace(
            ['+', '/', '='],
            ['-', '_', ''],
            \base64_encode($input)
        );
    }

    /**
     * Decode an "URL-safe" base64 encoded string.
     *
     * @param string $input
     *
     * @return string
     */
    protected function base64Decode($input)
    {
        return \base64_decode(
            \str_replace(
                ['-', '_'],
                ['+', '/'],
                $input
            )
        );
    }
}
