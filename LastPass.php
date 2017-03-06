<?php

/**
 * @file
 * LastPass-PHP library, designed to retrieve account information from LastPass.
 * @version 1.0.1
 * @license MIT
 */

/**
 * Lastpass CLI version, used when sending request to LastPass.
 */
define('LASTPASS_CLI_VERSION', '1.1.2');

/**
 * The user agent used when making requests to LastPass.
 */
define('LASTPASS_CLI_USERAGENT', 'LastPass-CLI/' . LASTPASS_CLI_VERSION);

/**
 * The LastPass server URL to send requests.
 */
define('LASTPASS_SERVER', 'https://lastpass.com');

/**
 * Represents the AES block size.
 */
define('AES_BLOCK_SIZE', 16);

/**
 * Represents the cipher method used for openssl_encrypt and openssl_decrypt.
 */
define('CIPHER_MODE_AES_CBC', 'AES-256-CBC');

/**
 * The length of the generated hash.
 */
define('KDF_HASH_LEN', 32);

/**
 * Represents the start text of the decrypted private key.
 */
define('LP_PKEY_PREFIX', 'LastPassPrivateKey<');

/**
 * Represents the end text of the decrypted private key.
 */
define('LP_PKEY_SUFFIX', '>LastPassPrivateKey');

class LPBlob {

  /**
   * @var object Holds all the user's LastPass information.
   */
  private $blob;

  /**
   * @var string The private key used to decrypt the blog contents.
   */
  private $privateKey;

  /**
   * Constructor, sets the blob and private key.
   *
   * @param string $blob
   *   The blob data to decrypt.
   * @param string $private_key
   *   The private key used to decrypt the blob data.
   */
  public function __construct($blob, $private_key) {
    $this->privateKey = $private_key;
    $this->blob = new stdClass();
    $this->blob->data = $blob;
    $this->blob->length = strlen($this->blob->data);
    $this->blob->position = 0;
  }

  /**
   * Parses the blob data with the private key.
   *
   * @return object
   *   The parsed blob data containing accounts, shared accounts, and
   */
  public function parse() {
    $parsed = new stdClass();

    $parsed->account = NULL;
    $parsed->accounts = array();

    $parsed->share = NULL;
    $parsed->shared = array();

    $parsed->app = NULL;

    while ($chunk = $this->readChunk($this->blob)) {
      if (empty($chunk)) {
        continue;
      }

      if ($chunk->name == 'LPAV') {
        $parsed->version = $chunk->data;
      }
      elseif ($chunk->name == 'ACCT') {
        $parsed->account = $this->accountParse($chunk, !empty($parsed->share) ? $parsed->share->key : $this->privateKey);
        $parsed->account->fields = array();
        $parsed->accounts[] = $parsed->account;
      }
      elseif ($chunk->name == 'ACFL' || $chunk->name == 'ACOF') {
        if (empty($parsed->account)) {
          continue;
        }

        $field = $this->fieldParse($chunk, !empty($parsed->share) ? $parsed->share->key : $this->privateKey);
        $parsed->account->fields[] = $field;
      }
      elseif ($chunk->name == 'LOCL') {
        $parsed->local_version = TRUE;
      }
      elseif ($chunk->name == 'SHAR') {
        $parsed->share = $this->shareParse($chunk, $this->privateKey);
        $parsed->shared[] = $parsed->share;
      }
      elseif ($chunk->name == 'AACT') {
        $parsed->app = $this->appParse($chunk, !empty($parsed->share) ? $parsed->share->key : $this->privateKey);
        $parsed->accounts[$parsed->id] = $parsed->app;
      }
      elseif ($chunk->name == 'AACF') {
        if (empty($parsed->app) || empty($parsed->account)) {
          continue;
        }

        $field = $this->appFieldParse($chunk, !empty($parsed->share) ? $parsed->share->key : $this->privateKey);
        $parsed->account->fields[] = $field;
      }
      elseif ($chunk->name == 'ATTA') {
        $attachment = $this->attachParse($chunk);
        if (!empty($attachment->parent) && !empty($parsed->accounts[$attachment->parent])) {
          $parsed->accounts[$attachment->parent]->attachments[] = $attachment;
        }
      }
    }

    return $parsed;
  }

  /**
   * Parses an app field and returns the parsed value.
   *
   * @param object $chunk
   *   The chunk object to parse.
   * @param stirng $key
   *   The key used for decoding encoded text.
   *
   * @return object
   *   The parsed app field.
   */
  private function appParse($chunk, $key) {
    $parsed = new stdClass();
    $parsed->account = new stdClass();

    $parsed->account->id = $this->entryPlain($chunk);
    $parsed->appname = $this->entryHex($chunk);
    $parsed->extra = $this->entryCrypt($chunk, $key);
    $parsed->account->name = $this->entryCrypt($chunk, $key);
    $parsed->account->group = $this->entryCrypt($chunk, $key);
    $parsed->account->last_touch = $this->entryPlain($chunk);
    $this->skip($chunk);
    $parsed->account->pwprotect = $this->entryBoolean($chunk);
    $parsed->account->fav = $this->entryBoolean($chunk);
    $parsed->wintitle = $this->entryPlain($chunk);
    $parsed->wininfo = $this->entryPlain($chunk);
    $parsed->exeversion = $this->entryPlain($chunk);
    $this->skip($chunk);
    $parsed->warnversion = $this->entryPlain($chunk);
    $parsed->exehash = $this->entryPlain($chunk);
    $parsed->account->username = '';
    $parsed->account->password = '';
    $parsed->account->note = '';
    $parsed->account->url = '';

    if (!empty($parsed->account->group) && (!empty($parsed->account->name) || $this->accountIsGroup($parsed))) {
      $parsed->account->fullname = $parsed->account->group . '/' . $parsed->account->name;
    }
    else {
      $parsed->account->fullname = $parsed->name;
    }

    return $parsed;
  }

  /**
   * Parses an app field.
   *
   * @param object $chunk
   *   The chunk object to parse.
   * @param string $key
   *   The key used for decoding encoded text.
   *
   * @return object
   *   The parsed app field object.
   */
  private function appFieldParse($chunk, $key) {
    $parsed = new stdClass();
    $parsed->name = $this->entryPlain($chunk);
    $parsed->value = $this->entryCrypt($chunk, $key);
    $parsed->type = $this->entryPlain($chunk);
    return $parsed;
  }

  /**
   * Parses an account and returns the parsed content.
   *
   * @param object $chunk
   *   The chunk object to parse.
   * @param string $key
   *   The key used for decoding encoded text.
   * @param bool $include_chunk
   *   TRUE to attach the chunk object to the parsed object. This was done in
   *   the original lastpass-cli code, but probably isn't needed.
   *
   * @return object
   *   The parsed account data.
   */
  private function accountParse($chunk, $key, $include_chunk = FALSE) {
    $parsed = new stdClass();
    if ($include_chunk) {
      $parsed->chunk = $chunk;
    }

    $parsed->id = $this->entryPlain($chunk);
    $parsed->name = $this->entryCrypt($chunk, $key);
    $parsed->group = $this->entryCrypt($chunk, $key);
    $parsed->url = $this->entryHex($chunk);
    $parsed->note = $this->entryCrypt($chunk, $key);
    $parsed->fav = $this->entryBoolean($chunk);
    $this->skip($chunk);
    $parsed->username = $this->entryCrypt($chunk, $key);
    $parsed->password = $this->entryCrypt($chunk, $key);
    $parsed->pwprotect = $this->entryBoolean($chunk);
    $this->skip($chunk);
    $this->skip($chunk);
    $parsed->last_touch = $this->entryPlain($chunk);
    $this->skip($chunk);
    $this->skip($chunk);
    $this->skip($chunk);
    $this->skip($chunk);
    $this->skip($chunk);
    $this->skip($chunk);
    $this->skip($chunk);
    $this->skip($chunk);
    $this->skip($chunk);
    $this->skip($chunk);
    $this->skip($chunk);
    $this->skip($chunk);
    $this->skip($chunk);
    $parsed->attachkey = '';
    $parsed->attachkey_encrypted = $this->entryPlain($chunk);
    $parsed->attachpresent = $this->entryBoolean($chunk);
    $this->skip($chunk);
    $this->skip($chunk);
    $this->skip($chunk);
    $parsed->last_modified_gmt = $this->entryPlain($chunk);
    $this->skip($chunk);
    $this->skip($chunk);
    $this->skip($chunk);
    $this->skip($chunk);

    if (!empty($parsed->name) && $parsed->name[0] == 16) {
      $parsed->name[0] = "\0";
    }

    if (!empty($parsed->group) && $parsed->group[0] == 16) {
      $parsed->group[0] = "\0";
    }

    if (!empty($parsed->attachkey_encrypted)) {
      $parsed->attachkey = LPCipher::cipherAESDecryptBase64($parsed->attachkey_encrypted, $key);
    }

    /* use name as 'fullname' only if there's no assigned group */
    if (strlen($parsed->group) && (strlen($parsed->name) || $this->accountIsGroup($parsed))) {
      $parsed->fullname = $parsed->group . '/' . $parsed->name;
    }
    else {
      $parsed->fullname = $parsed->name;
    }

    return $parsed;
  }

  /**
   * Returns if the account is a group account.
   *
   * @param object $account
   *   The account to check.
   *
   * @return bool
   *   TRUE if this account is a group.
   */
  private function accountIsGroup($account) {
    return strpos($account->url, "http://group") !== FALSE;
  }

  /**
   * Parses an attachment field.
   *
   * @param object $chunk
   *   The chunk to parse.
   *
   * @return object
   *   The parsed attachment object.
   */
  private function attachParse($chunk) {
    $parsed = new stdClass();
    $parsed->id = $this->entryPlain($chunk);
    $parsed->parent = $this->entryPlain($chunk);
    $parsed->mimetype = $this->entryPlain($chunk);
    $parsed->storagekey = $this->entryPlain($chunk);
    $parsed->size = $this->entryPlain($chunk);
    $parsed->filename = $this->entryPlain($chunk);
    return $parsed;
  }

  /**
   * Parses a shared field.
   *
   * @param object $chunk
   *   The chunk object to parse.
   * @param string $key
   *   The key used for decoding encoded text.
   * @param bool $include_chunk
   *   TRUE to attach the chunk object to the parsed object. This was done in
   *   the original lastpass-cli code, but probably isn't needed.
   *
   * @return object
   *   The parsed share object.
   */
  private function shareParse($chunk, $key, $include_chunk = FALSE) {
    $parsed = new stdClass();
    if ($include_chunk) {
      $parsed->chunk = $chunk;
    }
    $parsed->id = $this->entryPlain($chunk);

    $item = $this->readItem($chunk);
    if (!$item || $item->length == 0 || $item->length % 2 != 0) {
      return FALSE;
    }

    $ciphertext = LPUtil::hexToBytes($item->data);
    $rsa = new phpseclib\Crypt\RSA();
    $rsa->setEncryptionMode($rsa::ENCRYPTION_OAEP);
    $rsa->setPrivateKey($key, $rsa::PRIVATE_FORMAT_PKCS8);
    $hex_key = $rsa->decrypt($ciphertext);

    if (!$hex_key) {
      throw new Exception("Unable to decrypt private key.");
    }

    $len = strlen($hex_key);
    if ($len % 2 != 0) {
      throw new Exception("Invalid private key length, must be an even length.");
    }

    $len /= 2;
    if ($len != KDF_HASH_LEN) {
      throw new Exception(sprintf("Invalid private key, must be exactly %d characters.", KDF_HASH_LEN));
    }

    $parsed->key = LPUtil::hexToBytes($hex_key);
    $base64_name = $this->readItem($chunk)->data;
    $parsed->name = trim(LPCipher::cipherAESDecryptBase64($base64_name, $parsed->key));
    if (!$parsed->name) {
      return FALSE;
    }
    $parsed->readonly = (bool) $this->readItem($chunk)->data;

    return $parsed;
  }

  /**
   * Parses a field.
   *
   * @param object $chunk
   *   The chunk object to parse.
   * @param string $key
   *   The key used for decoding encoded text.
   *
   * @return object
   *   The parsed field.
   */
  private function fieldParse($chunk, $key) {
    $parsed = new stdClass();
    $parsed->name = $this->entryPlain($chunk);
    $parsed->type = $this->entryPlain($chunk);
    $crypt_types = array(
      'email',
      'tel',
      'text',
      'password',
      'textarea',
    );
    if (in_array($parsed->type, $crypt_types)) {
      $parsed->value = $this->entryCrypt($chunk, $key);
    }
    else {
      $parsed->value = $this->entryPlain($chunk);
    }
    $parsed->checked = $this->entryBoolean($chunk);
    return $parsed;
  }

  /**
   * Returns the next plain text entry from the chunk.
   *
   * @param object $chunk
   *   The chunk to use.
   *
   * @return string
   *   The next plain text entry from the chunk.
   */
  private function entryPlain($chunk) {
    return $this->readItem($chunk)->data;
  }

  /**
   * Returns the next decrypted text entry from the chunk.
   *
   * @param object $chunk
   *   The chunk to use.
   *
   * @return string
   *   The decrypted text entry from the chunk.
   */
  private function entryCrypt($chunk, $key) {
    $item = $this->readItem($chunk);
    if (!$item || $item->length == 0) {
      return NULL;
    }
    return trim(LPCipher::cipherAESDecrypt($item->data, $key));
  }

  /**
   * Returns the next hex entry from the chunk.
   *
   * @param object $chunk
   *   The chunk to use.
   *
   * @return string
   *   The next hex entry from the chunk.
   */
  private function entryHex($chunk) {
    $item = $this->readItem($chunk);
    if (!$item || $item->length == 0) {
      return NULL;
    }
    return LPUtil::hexToBytes($item->data);
  }

  /**
   * Returns the next boolean entry from the chunk.
   *
   * @param object $chunk
   *   The chunk to use.
   *
   * @return bool
   *   The next boolean entry from the chunk.
   */
  private function entryBoolean($chunk) {
    $item = $this->readItem($chunk);
    if (!$item) {
      return -1;
    }
    if ($item->length != 1) {
      return 0;
    }
    return $item->data[0] == '1';
  }

  /**
   * Skip the next entry in the chunk.
   *
   * @param object $chunk
   *   The chunk to use.
   */
  private function skip($chunk) {
    $this->readItem($chunk);
  }

  /**
   * Returns the next item from the chunk.
   *
   * @param object $chunk
   *   The chunk to use.
   *
   * @return object
   *   The next item from the chunk.
   */
  private function readItem($chunk) {
    if ($chunk->length < 4 || $chunk->position >= $chunk->length - 4) {
      return FALSE;
    }

    $item = new stdClass();
    $item->length = mb_substr($chunk->data, $chunk->position, 4, '8bit');
    $item->length = unpack("N", $item->length);
    $item->length = reset($item->length);
    $chunk->position += 4;
    if ($item->length > $chunk->length || $chunk->position >= $chunk->length - 4) {
      return FALSE;
    }

    $item->data = mb_substr($chunk->data, $chunk->position, $item->length, '8bit');
    $chunk->position += $item->length;
    return $item;
  }

  /**
   * Reads a chunk from the user's blob.
   *
   * @param object $blob
   *   The blob object to retrieve the chunk from.
   *
   * @return object
   *   The next chunk object from the blob.
   */
  private function readChunk($blob) {
    if ($blob->length - $blob->position < 4) {
      return FALSE;
    }

    $return_null = FALSE;
    $chunk = new stdClass();
    $chunk->name = mb_substr($blob->data, $blob->position, 4, '8bit');
    $blob->position += 4;

    $chunk->length = mb_substr($blob->data, $blob->position, 4, '8bit');
    $chunk->length = reset(unpack("N", $chunk->length));
    $blob->position += 4;

    $chunk->data = mb_substr($blob->data, $blob->position, $chunk->length + 4, '8bit');
    $blob->position += $chunk->length;

    $chunk->position = 0;

    return $chunk;
  }
}

class LPCipher {

  /**
   * @var object The \phpseclib\AES class used by this class.
   */
  private static $aes = NULL;

  /**
   * Decodes a specially formatted base64-encoded string.
   *
   * @param string $ciphertext
   *   The encoded string to decode.
   *
   * @return string
   *   The decoded text.
   */
  public static function cipherUnbase64($ciphertext) {
    if (!strlen($ciphertext)) {
      return FALSE;
    }

    if ($ciphertext[0] != '!') {
      return base64_decode($ciphertext);
    }

    $pipe = strpos($ciphertext, '|') + 1;
    if ($pipe === FALSE) {
      return FALSE;
    }

    $copy = base64_decode(substr($ciphertext, 1, $pipe - 1 /* pipe */ - 1 /* bang */));
    $pipe = base64_decode(substr($ciphertext, $pipe));

    return '!' . $copy . $pipe;
  }

  /**
   * Decrypts the provided string using the provided key.
   *
   * @param string $ciphertext
   *   The string to decrypt.
   * @param string $key
   *   The key used to decrypt the string.
   * @param int $len
   *   An optional parameter specifying the length of the encoded string.
   *
   * @return string
   *   The decrypted string.
   */
  public static function cipherAESDecrypt($ciphertext, $key, $len = NULL) {
    if (empty($len)) {
      $len = strlen($ciphertext);
    }

    $mode = $len >= 33 && $len % 16 == 1 && $ciphertext[0] == '!' ? 2 : 1;
    if (empty(static::$aes)) {
      static::$aes = new \phpseclib\Crypt\AES($mode);
    }
    else {
      static::$aes->mode = $mode;
    }

    $start = 0;
    if ($mode == 2) {
      static::$aes->setIV(mb_substr($ciphertext, 1, 16, '8bit'));
      $start = 17;
    }

    static::$aes->disablePadding();
    static::$aes->setKey($key);
    $ciphertext = mb_substr($ciphertext, $start, $len - $start, '8bit');
    $plaintext = static::$aes->decrypt($ciphertext);

    return $plaintext;
  }

  /**
   * Decrypts a base64-encoded string.
   *
   * @param string $ciphertext
   *   The base64-encoded string to decrypt.
   * @param string $key
   *   The key used to decrypt the string.
   *
   * @return string
   *   The decrypted contents of the string.
   */
  public static function cipherAESDecryptBase64($ciphertext, $key) {
    $ciphertext_unbase64 = static::cipherUnbase64($ciphertext);
    return static::cipherAESDecrypt($ciphertext_unbase64, $key);
  }

  /**
   * Decrypts a private key.
   *
   * @param string $key_hex
   *   The key used to decrypt the private key.
   * @param string $key
   *   The private key to decrypt.
   *
   * @return string
   *   The private key.
   */
  public static function cipherDecryptPrivateKey($key_hex, $key) {
    $len = mb_strlen($key_hex);
    if (!$len) {
      return FALSE;
    }

    if ($key_hex[0] == '!') {
      // v2 format
      $decrypted_key = static::cipherAESDecryptBase64($key_hex, $key);
    }
    elseif ($len % 2 != 0) {
      throw new Exception("Private key hex in wrong format.");
    }
    else {
      $len /= 2;
      $len += 16 + 1;
      // v1 format
      $encrypted_key = '!';
      $encrypted_key .= mb_substr($key, 0, 16, '8bit');
      $encrypted_key .= hex2bin($key_hex);
      $encrypted_key = mb_substr($encrypted_key, 0, $len, '8bit');
      $decrypted_key = static::cipherAESDecrypt($encrypted_key, $key, $len);
    }

    if (!$decrypted_key) {
      throw new Exception("Could not decrypt private key.");
    }

    $start = strpos($decrypted_key, LP_PKEY_PREFIX);
    $end = strpos($decrypted_key, LP_PKEY_SUFFIX);
    if ($start === FALSE || $end === FALSE || $end <= $start) {
      throw new Exception("Could not decode decrypted private key.");
    }

    $start += strlen(LP_PKEY_PREFIX);
    $end -= strlen(LP_PKEY_PREFIX);
    $decrypted_key = mb_substr($decrypted_key, $start, $end, '8bit');
    return LPUtil::hexToBytes($decrypted_key);
  }
}

class LPUtil {
  /**
   * Converts a hex string to bytes.
   *
   * @param string $data
   *   The hex string to convert to bytes.
   *
   * @return string
   *   The converted bytes.
   */
  public static function hexToBytes($data) {
    if (strlen($data) % 2 != 0) {
      throw new Exception('hexToBytes: invalid data length');
    }

    $encoded = array();
    $len = strlen($data) / 2;
    for ($i = 0; $i < $len; ++$i) {
      $encoded[] = hex2bin($data[$i * 2] . $data[$i * 2 + 1]);
    }
    return implode($encoded);
  }

  /**
   * Gets the amount of time in seconds from a date string.
   *
   * The format of the date string is [n years][,] [n months][,] [n days][,]
   * [n hours][,] [n minutes][,] [n seconds], where values in brackets are
   * optional. For example, the following all are valid strings to pass:
   *   1 year, 2 weeks, 30 seconds
   *   1 month; 5 days
   *   1 day 30 seconds
   *   1 minute
   *   2 days/5 years/3 hours
   *
   * @param string $string
   *   The string to parse.
   *
   * @return int
   *   The amount of time in seconds.
   */
  public static function getTimeFromString($string) {
    if (preg_match_all('/(\d+)\s?([a-z]*)/i', $string, $matches, PREG_SET_ORDER) !== FALSE) {
      $times = array(
        'years' => 0,
        'months' => 0,
        'weeks' => 0,
        'days' => 0,
        'hours' => 0,
        'minutes' => 0,
        'seconds' => 0,
      );
      foreach ($matches as $match) {
        $type = $match[2];
        if (strpos($type, 'year') !== FALSE) {
          $times['years'] = $match[1];
        }
        elseif (strpos($type, 'month') !== FALSE) {
          $times['months'] = $match[1];
        }
        elseif (strpos($type, 'week') !== FALSE) {
          $times['weeks'] = $match[1];
        }
        elseif (strpos($type, 'day') !== FALSE) {
          $times['days'] = $match[1];
        }
        elseif (strpos($type, 'hour') !== FALSE) {
          $times['hours'] = $match[1];
        }
        elseif (strpos($type, 'minute') !== FALSE) {
          $times['minutes'] = $match[1];
        }
        elseif (strpos($type, 'second') !== FALSE) {
          $times['seconds'] = $match[1];
        }
      }

      $times['years'] *= 360 * 24 * 60 * 60;
      $times['months'] *= 30 * 24 * 60 * 60;
      $times['weeks'] *= 7 * 24 * 60 * 60;
      $times['days'] *= 24 * 60 * 60;
      $times['hours'] *= 60 * 60;
      $times['minutes'] *= 60;

      array_filter($times);

      $total = array_reduce($times, function($carry, $item) {
        $carry += $item;
        return $carry;
      });
    }

    return $total;
  }

  /**
   * Scans $location and removes files that are older than the given time.
   *
   * @param string $location
   *   The folder location to scan.
   * @param int|string $delete_time
   *   The amount of time in seconds, or a date string that can be parsed by
   *   LPUtil::getTimeFromString, relative to the file's creation time in order
   *   to delete a file.
   */
  public static function purgeConfigFiles($location, $delete_time) {
    $saved_files = scandir($save_folder);

    foreach ($saved_files as $sf) {
      if (is_dir($sf)) {
        continue;
      }

      if (!is_numeric($delete_time)) {
        $delete_time = static::getTimeFromString($delete_time);
      }

      if (time() > filectime($filetime) + $delete_time) {
        $filename = $location . $sf;
        unlink($filename);
      }
    }
  }
}

class LastPass {

  private $username = NULL;

  private $password = NULL;

  private $options;

  private $iterations = 1;

  private $session = array();

  private $loginKey;

  private $decryptionKey;

  private $blob;

  private $iv;

  /**
   * Constructor.
   *
   * @param string $username
   *   The user's username.
   * @param string $password
   *   The user's password.
   * @param array $options
   *   An array of options to use.
   */
  public function __construct($username = NULL, $password = NULL, $options = array()) {
    $this->setUsername($username);
    $this->setPassword($password);
    $this->setOptions($options);
  }

  /**
   * Sets the user's username used to login to LastPass.
   *
   * @param string $username
   *   The user's username.
   */
  public function setUsername($username) {
    $this->username = strtolower($username);
  }

  /**
   * Sets the user's password used to login to LastPass.
   *
   * @param string $password
   *   The user's password.
   */
  public function setPassword($password) {
    $this->password = $password;
  }

  /**
   * Returns an array of default options to use.
   *
   * @return array
   *   An array of default options.
   */
  private function defaultOptions() {
    return array(
      /*
       * TRUE to save blob information to a file. The file name will be set to
       * "blob-{lastpass-user-id}". Not as fast as saving the blob to a session,
       * but better than not saving it at all, as it prevents the need of
       * sending multiple requests to LastPass in a short amount of time.
       */
      'savetofile' => FALSE,
      /*
       * The directory location to save blob information when "savetofile" is
       * TRUE. It's recommended to set this to a directory that can be
       * automatically purged, like "/tmp".
       */
      'savelocation' => '.',
      /*
       * TRUE to attempt to detect if locally stored blob information can be
       * deleted.
       */
      'autodeletesaves' => TRUE,
      /*
       * Can either be an integer representing the amount of time in seconds
       * relative to the file creation date a file can be removed, or a date
       * format which will automatically be converted to seconds.
       *
       * @see LPUtil::getTimeFromString for more information about the date
       * string format.
       */
      'autodeletetime' => NULL,
      /*
       * TRUE to save the blob information to a session. Much faster than
       * saving it to a file, but could increase memory consumption based on how
       * much data is in the blob.
       */
      'savetosession' => TRUE,
    );
  }

  /**
   * Sets the options this class will use.
   *
   * @param array $options
   *   An array of options.
   */
  public function setOptions($options) {
    $this->options = $this->defaultOptions() + $options;
  }

  /**
   * Gets the user's raw blob from LastPass.
   */
  private function getRawBlob() {
    try {
      $response = $this->request('getaccts', array(
        'mobile' => 1,
        'requestsrc' => 'cli',
        'hasplugin' => LASTPASS_CLI_VERSION,
      ), 'https://' . $this->session['logloginsvr']);
      return $response;
    }
    catch (Exception $e) {
      return $e->getMessage();
    }
  }

  /**
   * Retrieves and saves the parsed blob information for the LastPass user.
   */
  public function getBlob() {
    if (empty($this->session)) {
      $this->login();
    }

    $fetch_blob = FALSE;
    if (empty($this->blob)) {
      if ($this->options['savetosession']) {
        if (!empty($this->session['blob'])) {
          $this->blob = $this->session['blob'];
          return $this->session['blob'];
        }
        $raw_blob = $this->getRawBlob();
        $raw_blob = new LPBlob($raw_blob, $this->session['privatekey']);
        $this->blob = $raw_blob->parse();
        if (session_status() == PHP_SESSION_NONE) {
          session_start();
        }
        $_SESSION['lastpass']['blob'] = $this->blob;
        return $this->blob;
      }
      elseif ($this->options['savetofile']) {
        $raw_blob = $this->configReadEncryptedBuffer('blob-' . $this->session['uid'], $this->decryptionKey);
        if (empty($response)) {
          $raw_blob = $this->getRawBlob();
          $this->configWriteEncryptedBuffer('blob-' . $this->session['uid'], $response, $this->decryptionKey);
        }
        $raw_blob = new LPBlob($raw_blob, $this->session['privatekey']);
        $this->blob = $raw_blob->parse();
        return $this->blob;
      }
      else {
        $raw_blob = $this->getRawBlob();
        $raw_blob = new LPBlob($raw_blob, $this->session['privatekey']);
        $this->blob = $raw_blob->parse();
        return $this->blob;
      }
    }
  }

  /**
   * Search for a user's accounts based on the parameters given.
   *
   * @param string $search
   *   The search string to look for.
   *
   * @param array $fields_to_search
   *   The fields of each user's account to search and compare the search string
   *   against.
   *
   * @return array
   *   An array of matching accounts.
   */
  public function searchAccounts($search = '', $fields_to_search = array()) {
    $blob = $this->getBlob();
    $accounts = $blob->accounts;
    $found = array();
    if (!empty($search)) {
      if (empty($fields_to_search)) {
        $fields_to_search = array(
          'id',
          'name',
          'fullname',
          'url',
          'username',
        );
      }

      foreach ($accounts as $account) {
        foreach ($fields_to_search as $field) {
          if (strpos($account->{$field}, $search) !== FALSE) {
            $found[] = $account;
            break;
          }
        }
      }

      return $found;
    }

    return $accounts;
  }

  /**
   * Retrieves a path to the folder used to store files.
   *
   * @return string
   *   The stored folder path.
   */
  private function configFileLocation() {
    return $this->options['savelocation'] . DIRECTORY_SEPARATOR;
  }

  /**
   * Read encrypted contents from a file.
   *
   * @param string $name
   *   The name of the file to read.
   * @param string $key
   *   The key used to decrypt the contents.
   *
   * @return bool|string
   *   FALSE if an error occurred, otherwise the decrypted contents will be
   *   returned.
   */
  private function configReadEncryptedBuffer($name, $key) {
    if (!$this->options['savetofile']) {
      return FALSE;
    }

    $filename = $this->configFileLocation() . $name;
    if (!file_exists($filename)) {
      return FALSE;
    }

    $encrypted_buffer = file_get_contents($filename);
    if (!$encrypted_buffer) {
      return FALSE;
    }

    return $this->decryptBuffer($encrypted_buffer, $key);
  }

  /**
   * Write encrypted contents to a file.
   *
   * @param string $name
   *   The name of the file.
   * @param string $buffer
   *   The unencrypted contents to write to the file.
   * @param string $key
   *   The key to use to encrypt the contents.
   *
   * @return bool
   *   TRUE if the file was written to successfully, FALSE if an error occurred.
   */
  private function configWriteEncryptedBuffer($name, $buffer, $key) {
    if (!$this->options['savetofile']) {
      return FALSE;
    }

    $encrypted_buffer = $this->encryptBuffer($buffer, $key);
    if (!$encrypted_buffer) {
      return FALSE;
    }

    if (!in_array($name, $this->savedFiles)) {
      $this->savedFiles[] = $name;
    }

    return file_put_contents($this->configFileLocation() . $name, $encrypted_buffer);
  }

  /**
   * For config files, return the decrypted contents of $buffer.
   *
   * @param string $buffer
   *   The contents to decrypt.
   * @param string $key
   *   The key used to decrypt the contents.
   *
   * @return string
   *   The decrytped contents.
   */
  private function decryptBuffer($buffer, $key) {
    $this->iv = substr($buffer, 0, AES_BLOCK_SIZE);
    $buffer = substr($buffer, AES_BLOCK_SIZE);
    return openssl_decrypt($buffer, CIPHER_MODE_AES_CBC, $key, 0, $this->iv);
  }

  /**
   * For config files, return the encrypted contents of $buffer.
   *
   * @param string $buffer
   *   The contents to encrypt.
   * @param string $key
   *   The string used to encrypt the contents.
   *
   * @return string
   *   The encrypted contents.
   */
  private function encryptBuffer($buffer, $key) {
    $this->iv = openssl_random_pseudo_bytes(AES_BLOCK_SIZE);
    $encrypted_buffer = openssl_encrypt($buffer, CIPHER_MODE_AES_CBC, $key, 0, $this->iv);
    $encrypted_buffer = $this->iv . $encrypted_buffer;
    return $encrypted_buffer;
  }

  /**
   * Returns the currently set session.
   *
   * @return object
   *   The current session.
   */
  public function getSession() {
    if (empty($this->session)) {
      if (session_status() == PHP_SESSION_NONE) {
        session_start();
      }

      if (isset($_SESSION['lastpass'])) {
        $this->session = $_SESSION['lastpass'];
      }
    }

    return $this->session;
  }

  /**
   * Returns if the user is logged in or not.
   *
   * @return bool
   *   TRUE if the user is logged in to LastPass, FALSE otherwise.
   */
  public function isLoggedIn() {
    $this->getSession();
    return !empty($this->session);
  }

  /**
   * Sends a login request to LastPass and saves the result in session.
   */
  public function login() {
    if (empty($this->username) || empty($this->password)) {
      throw new LastPassException("Your username and password must be set before a request to login can be made.");
    }

    if (session_status() == PHP_SESSION_NONE) {
      session_start();
    }

    if (!empty($_SESSION['lastpass'])) {
      $this->session = $_SESSION['lastpass'];
      $session_fields = array('iterations', 'loginKey', 'decryptionKey');
      foreach ($session_fields as $sf) {
        if (!empty($this->session[$sf])) {
          $this->{$sf} = $this->session[$sf];
        }
      }
    }
    else {
      $this->getIterations();
    }

    if (empty($this->session)) {
      $this->loginKey = $this->generateLoginKey($this->username, $this->password, $this->iterations);
      $this->decryptionKey = $this->generateDecryptionKey($this->username, $this->password, $this->iterations);

      $params = array(
        'xml' => '2',
        'username' => $this->username,
        'hash' => $this->loginKey,
        'iterations' => $this->iterations,
        'includeprivatekeyenc' => 1,
        'method' => 'cli',
        'outofbandsupported' => 1,
      );
      $response = $this->request('login', $params);
      $xml = simplexml_load_string($response);
      $xml = json_decode(json_encode($xml));
      if (!empty($xml->ok)) {
        // Save the session information.
        $root = $xml->ok->{'@attributes'};
        $this->session = array(
          'uid' => $root->uid,
          'sessionid' => $root->sessionid,
          'privatekeyenc' => $root->privatekeyenc,
          'lpusername' => $root->lpusername,
          'email' => $root->email,
          'pwdeckey' => $root->pwdeckey,
          'token' => $root->token,
          'iterations' => $root->iterations,
          'logloginsvr' => $root->logloginsvr,
          'loginKey' => $this->loginKey,
          'decryptionKey' => $this->decryptionKey,
        );
        $_SESSION['lastpass'] = $this->session;
      }
      elseif (!empty($xml->error)) {
        throw new LastPassException($xml->error->{'@attributes'}->message);
      }
      else {
        throw new LastPassException("Unexpected response from LastPass server.");
      }
    }

    if (empty($this->session['privatekey'])) {
      $this->session['privatekey'] = $_SESSION['lastpass']['privatekey'] = LPCipher::cipherDecryptPrivateKey($this->session['privatekeyenc'], $this->decryptionKey);
    }

    return TRUE;
  }

  /**
   * Destroy any locally saved information for the user and log them out.
   */
  public function logout() {
    if (session_status() == PHP_SESSION_NONE) {
      session_start();
    }

    if (!empty($_SESSION['lastpass'])) {
      unset($_SESSION['lastpass']);
    }

    // Remove any config files.
    if ($this->options['savetofile'] && $this->options['autodeletesaves']) {
      LPUtil::purgeConfigFiles($this->configFileLocation(), NULL);
    }
  }

  /**
   * Gets a LastPass user's iterations value.
   *
   * @return int
   *   The LastPass user's iterations value.
   */
  private function getIterations() {
    try {
      $this->iterations = $this->request('iterations', array(
        'email' => $this->username,
      ));
    }
    catch (Exception $e) {
      return FALSE;
    }

    if ($this->iterations < 1) {
      $this->iterations = 1;
    }

    return $this->iterations;
  }

  /**
   * Sends a cURL request to the specified LastPass server.
   *
   * @param string $action
   *   The action to send, i.e. login, getaccts, etc.
   * @param string $variables
   *   The variables to send.
   * @param string $login_server
   *   The LastPass server to send the request to.
   *
   * @return string
   *   The cURL response.
   */
  private function request($action, $variables, $login_server = LASTPASS_SERVER) {
    $ch = curl_init();
    $url = $login_server . '/' . $action . '.php';

    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_USERAGENT, LASTPASS_CLI_USERAGENT);
    curl_setopt($ch, CURLOPT_VERBOSE, 0);
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($variables));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_NOPROGRESS, 1);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 0);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 1);
    curl_setopt($ch, CURLOPT_FAILONERROR, 1);

    if (!empty($this->session)) {
      $cookie = "PHPSESSID=" . $this->session['sessionid'];
      curl_setopt($ch, CURLOPT_COOKIE, $cookie);
    }

    $response = curl_exec($ch);

    if ($error = curl_error($ch)) {
      throw new Exception('Could not complete request to LastPass: ' . $error);
    }

    curl_close($ch);
    return $response;
  }

  /**
   * Returns a SHA256 hash.
   *
   * @param string $username
   *   The user's LastPass username.
   * @param string $password
   *   The user's LastPass password.
   *
   * @return string
   *   The hash string.
   */
  private function sha256hash($username, $password) {
    $hash = hash_init('sha256');
    hash_update($hash, $username);
    hash_update($hash, $password);
    return hash_final($hash);
  }

  /**
   * Returns a PBKDF2 hash.
   *
   * @param string $username
   *   The user's LastPass username.
   * @param string $password
   *   The user's LastPass password.
   * @param int $iterations
   *   The user's number of LastPass account iterations.
   * @param int $length
   *   The length of the hash.
   *
   * @return string
   *   The hash string.
   */
  private function pbkdf2hash($username, $password, $iterations, $length = KDF_HASH_LEN) {
    return hash_pbkdf2('sha256', $password, $username, $iterations, $length, TRUE);
  }

  /**
   * Generates the user's login key.
   *
   * @param string $username
   *   The user's LastPass username.
   * @param string $password
   *   The user's LastPass password.
   * @param int $iterations
   *   The user's number of LastPass account iterations.
   *
   * @return string
   *   The user's login key.
   */
  private function generateLoginKey($username, $password, $iterations) {
    if ($iterations == 1) {
      $hash = $this->sha256hash($username, $password);
      $hex = bin2hex($hash);
      $hash = $this->sha256hash($hex, $password);
    }
    else {
      $hash = $this->pbkdf2hash($username, $password, $iterations);
      $hash = $this->pbkdf2hash($password, $hash, 1);
    }

    return bin2hex($hash);
  }

  /**
   * Generates the user's decryption key.
   *
   * @param string $username
   *   The user's LastPass username.
   * @param string $password
   *   The user's LastPass password.
   * @param int $iterations
   *   The user's number of LastPass account iterations.
   *
   * @return string
   *   The user's decryption key.
   */
  private function generateDecryptionKey($username, $password, $iterations) {
    if ($iterations == 1) {
      return $this->sha256hash($username, $password);
    }
    else {
      return $this->pbkdf2hash($username, $password, $iterations);
    }
  }

  /**
   * Check if any files that were saved to disk can be deleted.
   */
  public function __destruct() {
    // Remove any config files.
    if ($this->options['savetofile'] && $this->options['autodeletesaves']) {
      LPUtil::purgeConfigFiles($this->configFileLocation(), $this->options['autodeletetime']);
    }
  }
}

class LastPassException extends Exception {

}
