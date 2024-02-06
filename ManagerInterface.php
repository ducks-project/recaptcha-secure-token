<?php

namespace DucksProject\Component\RecaptchaSecureToken;

interface ManagerInterface
{
    public const CYPHER = 'aes-128-ecb';
    public function encode(string $session_id, ?float $timestamp = null): string;
    public function decode(string $token): array;
}
