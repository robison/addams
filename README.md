# morticia

`morticia` is a Python library to access, parse, and output a complete, JSON-formatted account configuration from the Gomez Performance Network.


## Usage:

`python pugsley.py -u \<username\> -p \<password\>`

## Output:

`pugsley` output breaks out account information by monitor. Information gathered includes:
- Monitor-specific information ("monitor":)
- Sites being used by the monitor ("sites":)
- Gomez Script Recorder script being used by the monitor ("script":)
- Alerting configuration used by the monitor ("alerts":)

Any information that's normally encoded via base64 will be recursed as JSON key/value pairs; this provides some semblance of human-readability, and allows the export/transposition of these configurations into other tools such as Selenium.

Built based on Nordstrom's Compuware GPN Splunk plugin - https://github.com/nordstrom/compuware_apm_gpn

Pull requests & feedback welcome.
