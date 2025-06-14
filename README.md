# CloudFail
Because CloudFail has aged quite a bit, it needs some updates. This fork aims to solve the issues that stopped CloudFail from working.

CloudFail is a tactical reconnaissance tool which aims to gather enough information about a target protected by Cloudflare in the hopes of discovering the location of the server. Using Tor to mask all requests, the tool as of right now has 3 different attack phases.

1. Misconfigured DNS scan using DNSDumpster.com.
2. Scan the Crimeflare database.
3. Bruteforce scan over 2500 subdomains.

![Example usage](http://puu.sh/pq7vH/62d56aa41f.png "Example usage")

> Please feel free to contribute to this project. If you have an idea or improvement issue a pull request!

<dl>
    <h3>How does this differ from the original?</h3>
        <dd>
            Not by much, hopefully.<br />
            This was forked with the intention of making the project work again, as DNSDumpster had changed the way they handled their API the original no longer worked.<br />
            We achieved that pretty easily, and with some help improved data sources and error handling. So make sure to read the changelog!
        </dd>
    <h3>New Features</h3>
        <dd>
            So far there aren't many, but let's change that together.
            <ul>
                <li>Report Generator</li>
                <li>IP List Output</li>
                <li>Updated Project Structure</li>
                <li>Updated DNSDumpster API Handling</li>
                <li>TOR Fix</li>
                <li>Quality of Life</li>
            </ul>
        </dd>
</dl>

## Disclaimer
This tool is a PoC (Proof of Concept) and does not guarantee results.  It is possible to setup Cloudflare properly so that the IP is never released or logged anywhere; this is not often the case and hence why this tool exists.
This tool is only for academic purposes and testing  under controlled environments. Do not use without obtaining proper authorization
from the network owner of the network under testing.
The author(s) bears no responsibility for any misuse of the tool.

## Docker

<details><summary>Prerequisites</summary>
  
You'll need to register an account with [DNSDumpster](https://dnsdumpster.com/), they have several tiers including a free one which is limited to 50 API calls and 50 records per day. Usually this is within scope.


We'll need the API key from the [My Account](https://dnsdumpster.com/my-account/) page for our environment, so keep it safe.

</details>

First, clone the repository:

```sh
git clone https://github.com/cnoid/CloudFail.git && cd CloudFail/
```

You have two choices on how to use the API key:
- Insert it into `.env`
- Use it as a docker environment command

Next, let's build it:

```sh
docker build -t cloudfail .
```

Next, let's run it the first time. Examples:

```sh
docker run --name cloudfail cloudfail:latest --help
```
Without `.env`:

```sh
docker run --name cloudfail -e DNSDUMPSTER_API_KEY=aaaabbbbccccddddd cloudfail:latest -t example.com
```

With `.env`:

```sh
docker run --name cloudfail cloudfail:latest -t example.com
```

You can now reuse the container:

```sh
docker start -i cloudfail -t example.com
```

## Install
Most (if not all) distributions come with Python installed already, I recommend installing `python-is-python3` if your distribution has it. However, if you do not have Python installed:

<details><summary>Debian based</summary>
First we need to install pip3 for python3 dependencies:

```sh
sudo apt-get install python3-pip
```

If pip install fails, try installing `python3-setuptools`

```sh
sudo apt-get install python3-setuptools
```

Recommendation: Install `python-is-python3`

```sh
sudo apt-get install python-is-python3
```

</details>

<details><summary>Arch based</summary>
Arch should come with this installed by default, however, this installs both python3 and pip:

```sh
sudo pacman -Sy python-pip
```

If the pip install fails, make sure you have `python-setuptools`:

```sh
sudo pacman -Sy python-setuptools
```

In Arch, `python` is `python3` by default.

</details>

Once you've confirmed this, let's install the requirements:

<details><summary>pip</summary>
First, set up a virtual environment:

```sh
python -m venv venv/
```

Then source it:

```sh
source venv/bin/activate
```

Now we can install our requirements:

```sh
pip install -r requirements.txt
```

</details>

<details><summary>pipx</summary>

```sh
pipx install -r requirements.txt
```

</details>

### Preconfiguration requirements
You'll need to register an account with [DNSDumpster](https://dnsdumpster.com/), they have several tiers including a free one which is limited to 50 API calls and 50 records per day. Usually this is within scope.


Once you have your API key from [My Account](https://dnsdumpster.com/my-account/) page, simply paste it into the `.env`, no quotation marks.

## Usage
```sh
   ____ _                 _ _____     _ _
  / ___| | ___  _   _  __| |  ___|_ _(_) |
 | |   | |/ _ \| | | |/ _` | |_ / _` | | |
 | |___| | (_) | |_| | (_| |  _| (_| | | |
  \____|_|\___/ \__,_|\__,_|_|  \__,_|_|_|
    v1.0.6                      by m0rtem / updated by cnoid, Soensh


[23:56:02] Initializing CloudFail - the date is: 23/01/2025  
usage: cloudfail.py [-h] [-t TARGET] [-T] [-u] [-i INPUT] [-r [REPORT ...]] [-o OUTPUT]

options:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        target url of website
  -T, --tor             enable TOR routing
  -u, --update          update databases
  -i INPUT, --input INPUT
                        path to input file containing subdomains
  -r [REPORT ...], --report [REPORT ...]
                        generate reports (html, md, ip, sub, all)
  -o OUTPUT, --output OUTPUT
                        output file for reports
```

To run a scan against a target:

```sh
python cloudfail.py --target seo.com
```

To run a scan against a target using a custom subdomain list:

```sh
python cloudfail.py -i subdomains.txt --target seo.com
```

To run a scan against a target using Tor:

```sh
service tor start
```

(or if you are using Windows or Mac install vidalia or just run the Tor browser)

```sh
python cloudfail.py --target seo.com --tor
```

To generate a HTML report

```sh
python cloudfail.py --target seo.com --report html --output seoreport.html
```

To generate an IP list

```sh
python cloudfail.py --target seo.com --report ip --output ip.txt
```

To generate all reports (HTML, MD, IP list, Subdomain list)

```sh
python cloudfail.py --target seo.com --report all --output seoreport
```

> Make sure you're running with Python 3. These commands are done with `python-is-python3` or equivalent.

#### Reports
Reports are now integrated into CloudFail.\
The templates are under `lib/util/reports/` where you may modify the templates to your choosing, such as stylizing the HTML file to fit your needs.

Reports have 5 output modes: `html`, `md`, `ip`, `sub` and `all`. They're not mutually exclusive and can be used together.\
Generate an IP list: `-r ip`<br />
Generate a HTML report: `-r html`<br />
Generate a MarkDown report: `-r md`<br />
Generate a Subdomain List: `-r sub`<br />
Generate all: `-r all`


#### Dependencies
**Python3**
* argparse
* colorama
* socket
* binascii
* datetime
* requests
* win_inet_pton
* dnspython

## Changelog

23/01/2025:

- Added reports
    - HTML and MarkDown reports
    - IP list output
    - Subdomain output
- Restructured project

22/01/2025:\
Thanks to @pykereaper

- [skip DNSDumpster when no API key is set](https://github.com/0xnoid/CloudFail/pull/1)
- [Tor: Fix public IP server error](https://github.com/0xnoid/CloudFail/pull/2)

09/01/2025:

- Updated API call to match dnsdumpster (including API key requirement)
- Added .env for dnsdumpster API key
- Changed Docker image to use python-slim instead of Debian
- Added Docker entrypoint for reusing containers
- Updated finished message to display found IPs
- Changed interaction with input files

14/06/2025

[Fork by SoenSh. Personal use improvings.](https://github.com/fagneralc/CloudFailF)

- Liner arg, skipping subdomain enumeration
- DonWantEnumerate logic.
- Some loops
- Some minors additions
