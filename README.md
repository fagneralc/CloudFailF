# CloudFail
Because CloudFail has aged quite a bit, it needs some updates. This fork aims to solve the issues that stopped CloudFail from working.

CloudFail is a tactical reconnaissance tool which aims to gather enough information about a target protected by Cloudflare in the hopes of discovering the location of the server. Using Tor to mask all requests, the tool as of right now has 3 different attack phases.

1. Misconfigured DNS scan using DNSDumpster.com.
2. Scan the Crimeflare database.
3. Bruteforce scan over 2500 subdomains.

![Example usage](http://puu.sh/pq7vH/62d56aa41f.png "Example usage")

> Please feel free to contribute to this project. If you have an idea or improvement issue a pull request!

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

```
git clone https://github.com/cnoid/CloudFail.git && cd CloudFail/
```

You have two choices on how to use the API key:
- Insert it into `.env`
- Use it as a docker environment command

Next, let's build it:

```
docker build -t cloudfail .
```

Next, let's run it the first time. Examples:

```
docker run --name cloudfail cloudfail:latest --help
```
Without `.env`:

```
docker run --name cloudfail -e DNSDUMPSTER_API_KEY=aaaabbbbccccddddd cloudfail:latest -t example.com
```

With `.env`:

```
docker run --name cloudfail cloudfail:latest -t example.com
```

You can now reuse the container:

```
docker start -i cloudfail -t example.com
```

## Install
Most (if not all) distributions come with Python installed already, I recommend installing `python-is-python3` if your distribution has it. However, if you do not have Python installed:

<details><summary>Debian based</summary>
First we need to install pip3 for python3 dependencies:

```
sudo apt-get install python3-pip
```

If pip install fails, try installing `python3-setuptools`

```
sudo apt-get install python3-setuptools
```

Recommendation: Install `python-is-python3`

```
sudo apt-get install python-is-python3
```

</details>

<details><summary>Arch based</summary>
Arch should come with this installed by default, however, this installs both python3 and pip:

```
sudo pacman -Sy python-pip
```

If the pip install fails, make sure you have `python-setuptools`:

```
sudo pacman -Sy python-setuptools
```

In Arch, `python` is `python3` by default.

</details>

Once you've confirmed this, let's install the requirements:

<details><summary>pip</summary>
First, set up a virtual environment:

```
python -m venv venv/
```

Then source it:

```
source venv/bin/activate
```

Now we can install our requirements:

```
pip install -r requirements.txt
```

</details>

<details><summary>pipx</summary>

```
pipx install -r requirements.txt
```

</details>

### Preconfiguration requirements
You'll need to register an account with [DNSDumpster](https://dnsdumpster.com/), they have several tiers including a free one which is limited to 50 API calls and 50 records per day. Usually this is within scope.


Once you have your API key from [My Account](https://dnsdumpster.com/my-account/) page, simply paste it into the `.env`, no quotation marks.

## Usage

To run a scan against a target:

```
python cloudfail.py --target seo.com
```

To run a scan against a target using a custom subdomain list:

```
python cloudfail.py -i subdomains.txt --target seo.com
```

To run a scan against a target using Tor:

```
service tor start
```

(or if you are using Windows or Mac install vidalia or just run the Tor browser)

```
python cloudfail.py --target seo.com --tor
```

> Make sure you're running with Python 3. These commands are done with `python-is-python3` or equivalent.


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

<details>

- Updated API call to match dnsdumpster (including API key requirement)
- Added .env for dnsdumpster API key
- Changed Docker image to use python-slim instead of Debian
- Added Docker entrypoint for reusing containers
- Updated finished message to display found IPs
- Changed interaction with input files

</details>
