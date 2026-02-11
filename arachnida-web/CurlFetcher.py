class CurlFetcher:
    def __init__(self, timeout):
        self.c = pycurl.Curl()
        self.c.setopt(pycurl.FOLLOWLOCATION, 1)
        self.c.setopt(pycurl.TIMEOUT, timeout)
        self.c.setopt(pycurl.ACCEPT_ENCODING, "")
        self.buf = io.BytesIO()
        self.hdr = io.BytesIO()

    def get(self, url, headers):
        self.buf.seek(0); self.buf.truncate(0)
        self.hdr.seek(0); self.hdr.truncate(0)

        self.c.setopt(pycurl.URL, url)
        self.c.setopt(pycurl.WRITEDATA, self.buf)
        self.c.setopt(pycurl.HEADERFUNCTION, self.hdr.write)
        self.c.setopt(pycurl.HTTPHEADER, headers)

        self.c.perform()
        return self.c.getinfo(pycurl.RESPONSE_CODE), self.buf.getvalue()

