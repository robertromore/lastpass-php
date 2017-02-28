# lastpass-php

This is an unofficial, partial port of the lastpass-cli project, and is used to retrieve a user's stored accounts' information from LastPass with PHP. This project is not associated with LastPass in any way.

# requirements

In order to use this, you will need PHP with the OpenSSL extension, and the [phpseclib library](https://github.com/phpseclib/phpseclib).

# example usage

An example of getting a user's stored LastPass information:

```php

<?php

require_once "path/to/phpseclib";
require_once "path/to/lastpass-php";

$LP = new LastPass("username", "password");
$all_accounts = $LP->searchAccounts();
// The searchAccounts method also accepts two parameters:
// $search (string) The text to search for.
// $fields_to_search (array) An array of account fields to search through. By default, this method searches all fields: id, name, fullname, url, and username.
$mysite_account = $LP->searchAccounts("mysite", array("url"));

?>

```
