# CTPyClient

Python Certificate Transparency client

A collection of utilities to explore CT log servers.

## `monitor.py`

This utility implements a very basic CT client to fetch entries
from a CT log and display the certificates that are retrieved.

Usage:

```
monitor.py [number of log entries relative to last log entry to fetch]
```

## 'fetchroots.py'

This utility retrieves the list of trusted roots for a given log server

Usage:

````
fetchroots.py
````

## 'submitcert.py'

This utility submits a certificate and any intermediates to a given log server.
The utility supports both PEM encoded and binary DER encoded certificates as input.
The first certificate passed in as an argument is the end-entity cert, followed by each
subordinate CA certificate that chains to a root in the given log.

Usage:

````
submitcert.py [end entity cert] .. [subca1] .. [subcaN]
````

Install through `pip` using the requirements file:

```
pip install -r requirements.txt
```

or manually install the following:

* pyopenssl
* requests
* pyasn1
* pyasn1-modules
* ndg-httpsclient

Currently, `monitor.py` is hardcoded to use Google's log servers.
