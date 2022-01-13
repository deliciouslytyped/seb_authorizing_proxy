#! /usr/bin/env bash
#! nix-shell -i python -p "python38.withPackages (p: with p; [ mitmproxy lxml pycryptodome ])" -v

# nix-polyloader

"""true"
SCRIPT_PATH="$(realpath -s "$BASH_SOURCE")"
if ! command -v nix-shell; then
  exec python "$SCRIPT_PATH" "$@"
else
  exec nix-shell "$SCRIPT_PATH" "$@"
fi
"true"""

# Python starts

## LICENSE ##
# This testing tool is licensed public domain, insofar as the authors may license it such.
# The authors have not confirmed that they may do so.
# Any and all responsibility for usage of this program rests solely with the users.
##

## Changelog
#  Jan-13-2022 Initial release.
##

# This code roughly implements an authorizing proxy to the SEB Moodle plugin.
# It's based on the code of the windows client and the moodle plugin source code.
# At least according to https://github.com/catalyst/moodle-quizaccess_seb/blob/master/classes/access_manager.php ,
# and https://github.com/catalyst/moodle-quizaccess_seb/blob/bff0a7dfe976cc404e4004ed7a6dd1393afc1dbd/rule.php#L286
# we need to set the user-agent and the two headers.

# The configuration and exam keys are described in the following documents:
# https://safeexambrowser.org/developer/seb-config-key.html
# https://safeexambrowser.org/developer/documents/SEB-Specification-BrowserExamKey.pdf
# Platform specific information for the browserExamKey must be derived by digging through the source.

# The decryption code was referenced from the python implementation of https://github.com/RNCryptor/RNCryptor-python

# Other information was generally derived from inspecting the source code of several repositories,
# cross referencing with test cases, and inspecting the output of the windows configuration tool;
# https://github.com/catalyst/moodle-quizaccess_seb/
# https://github.com/SafeExamBrowser/seb-mac/
# https://github.com/SafeExamBrowser/seb-win-refactoring/

# TODO local and remote test cases
# need to test:
#  - invocations:
#     - w/wout nix
#     - exec / as mitmproxy script
#  - with encrypted / unencrypted SEB

# TODO consider writing a firefox addon instead, it would certainly ease deployment.
# TODO maybe bother to link the appropriate sections of upstream code where appropriate
# TODO safety note about test getting locked when?

import sys, os, re, base64, json, hmac
from collections import defaultdict, OrderedDict
from hashlib import sha256

import lxml.etree as ET

# TODO figure out why osslsigncode was giving the "wrong" signature
#  (ended up getting the right one with the windows properties dialog)
# TODO write some code to extract a signature / create a database?
Signatures = {
  "3_3_1_win_gh_rel" : (b"e89799f0033c61c5366d1c8cb4ec5852a864a530", b"3.3.1.388")
  }


class SEBConfig:
  def __init__(self, confFile, password):
    t = ET.fromstring(self.decrypt(confFile, password))
    self.genConfigKey(t)

    #TODO not sure if complexity should be increased by trying to add the headers only to pages that are "in scope"
    # The other relevant piece of code is in the mitmproxy section
    #self.urlregex = t.xpath(".//*[.='whitelistURLFilter']/following-sibling::*[1]")[0].text
    self.examkeysalt = base64.b64decode(t.xpath(".//*[.='examKeySalt']/following-sibling::*[1]")[0].text)
    self.genBrowserExamKey(self.examkeysalt)

  def genBrowserExamKey(self, salt):
    sig, ver = Signatures["3_3_1_win_gh_rel"]
    self.browserKey = hmac.new(salt, sig.upper() + ver + self.configKey, sha256).hexdigest()
    if "DEBUG" in os.environ:
      print(self.browserKey, file=sys.stderr)

  def genConfigKey(self, tree):
    jsn = json.dumps(self.toJSON(tree), separators=(',', ':')).replace("\\\\","\\").encode("utf-8")
    h = sha256()
    h.update(jsn)
    self.configKey = h.hexdigest().encode("utf-8") #TODO weird escaping s***?

  #TODO split into two functions
  def decrypt(self, fpath, password):
    import gzip
    import zlib

    with open(fpath, "rb") as ff:
      if ff.read(2) == b"\x1f\x8b":
        with gzip.open(fpath, 'rb') as f:
          file_content = f.read()
      else:
        ff.seek(0)
        file_content = ff.read()

    if password:
      decrypted_data = self._decrypt(file_content[4:], password)
      decompressed_data = zlib.decompress(decrypted_data,15 + 32)
    else:
      decompressed_data = file_content

    return decompressed_data

  # inlined from the python version of rncryptor
  def _decrypt(self, data, password):
    # DO NOT COPY THIS FOR ANYTHING SECURITY SENSITIVE 
    from hashlib import sha1, sha256
    import hmac
    from Crypto import Random
    from Crypto.Cipher import AES
    from Crypto.Protocol import KDF

    password = password.encode("utf-8")
    n = len(data)

    encryption_salt, hmac_salt, iv, ciphertext = data[2:10], data[10:18], data[18:34], data[34:n - 32]
    _hmac = data[n - 32:]

    prf = lambda secret, salt: hmac.new(secret, salt, sha1).digest()
    encryption_key = KDF.PBKDF2(password, encryption_salt, dkLen=32, count=10000, prf=prf)
    hmac_key = KDF.PBKDF2(password, hmac_salt, dkLen=32, count=10000, prf=prf)

    if not hmac.new(hmac_key, data[:n - 32], sha256).digest() == _hmac:
      raise DecryptionError("Bad data") #TODO not implemented

    decrypted = AES.new(encryption_key, AES.MODE_CBC, iv).decrypt(ciphertext)
    decrypted = decrypted[:-(decrypted[-1])]
    return decrypted

  # As specified by https://safeexambrowser.org/developer/seb-config-key.html
  def toJSON(self, e):
    assert(e.tag == 'plist')

    # https://stackoverflow.com/questions/5389507/iterating-over-every-two-elements-in-a-list
    def pairwise(iterable):
      a = iter(iterable)
      return zip(a, a)

    def unimp():
      raise NotImplementedError

    def not_empty_dict(e):
      return not (e.tag == 'dict' and len(e.getchildren()) == 0)

    #TODO this could use some tests, if for nothing else, the next poor soul.
    # Though, this is something like a thirdhand implementation - 
    # Who knows what parser differentials lurk in the shadows.
    dispatch = defaultdict(unimp, #TODO date
      { 'dict' : lambda e: OrderedDict(
          sorted(
            ((k.text, dispatch[v.tag](v)) for k,v in pairwise(e.iterchildren()) if k.text != "originatorVersion"),
            key=lambda x: x[0].lower()
            )
          )
      , 'array' : lambda e: [ dispatch[x.tag](x) for x in e.iterchildren() if not_empty_dict(x) ]
      , 'plist' : lambda e: dispatch['array'](e)[0] # a bit hacky
      , 'true' : lambda e: True
      , 'false' : lambda e: False
      , 'integer' : lambda e: int(e.text)
      , 'string' : lambda e: e.text if e.text else ""
      , 'data' : lambda e: e.text.strip() # Note, we don't unbase64 this here
      })

    return dispatch['plist'](e)


class SessionHandler:
  def __init__(self, config):
    self.config = config

  def getRequestHash(self, absurl):
    h = sha256()
    h.update(absurl.encode("utf-8"))
    h.update(self.config.browserKey.encode("utf-8"))
    return h.hexdigest()

  def getConfigHash(self, absurl):
    h = sha256()
    h.update(absurl.encode("utf-8"))
    h.update(self.config.configKey)
    return h.hexdigest()

  def matchTarget(self, url):
    return re.match(self.urlregex, url)


class SEBHeader:
  def __init__(self, ctx, conf):
    self.sess = SessionHandler(conf)
    self.ctx = ctx

  def request(self, flow):
    url = flow.request.url
    if True: # self.conf.matchTarget(url): #TODO y/n filter?
      self.ctx.log.info("SEBHeader applied to %s" % url)
      flow.request.headers["X-SafeExamBrowser-ConfigKeyHash"] = self.sess.getConfigHash(url)
      flow.request.headers["X-SafeExamBrowser-RequestHash"] = self.sess.getRequestHash(url)
      flow.request.headers["User-Agent"] += " SEB" #TODO could be better?


def start_proxy(confFile, password):
  from mitmproxy.options import Options
  from mitmproxy.proxy.config import ProxyConfig
  from mitmproxy.proxy.server import ProxyServer
  from mitmproxy.tools import console
  from mitmproxy import ctx

  options = Options(listen_host='0.0.0.0', listen_port=int(sys.argv[3]), http2=True)
  # Derived from inspecting the source of the call chain of the mitmproxy executable and TODO
  master = console.master.ConsoleMaster(options)
  master.server = ProxyServer(ProxyConfig(options))
  conf = SEBConfig(confFile, password)
  master.addons.add(SEBHeader(ctx, conf))
  master.run()


if __name__ == '__main__':
  if len(sys.argv) < 4:
    print(sys.argv)
    print("usage: seb_rewrite SEB_CONFIG_FILE PASSWORD PORT\n"
          "example: python3 seb_rewrite.py config.seb somePassword 8080\n"
          "# This testing tool is licensed public domain, insofar as the authors may license it such. #\n"
          "# The authors have not confirmed that they may do so.                                      #\n"
          "# Any and all responsibility for usage of this program rests solely with the users.        #\n")
    sys.exit(1)
  start_proxy(sys.argv[1], sys.argv[2])
else: # passed as script to mitmproxy #TODO test
  addons = [ SEBHeader(SEBConfig(confFile, password)) ]
