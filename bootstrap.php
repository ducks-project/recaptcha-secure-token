<?php

/**
 * Polyfill.
 */

if (!\class_exists('\\ReCaptchaSecureToken\\ReCaptchaToken', false)) {
    \class_alias('\\Ducks\\Component\\RecaptchaSecureToken\\Manager', '\\ReCaptchaSecureToken\\ReCaptchaToken', true);
}
