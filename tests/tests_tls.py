import ssl

def test_cert_load():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain("certs/server.crt", "certs/server.key")
    assert context is not None
