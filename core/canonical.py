import rfc8785


def canonicalize(data: dict) -> bytes:
    """
    Convierte un objeto Python en JSON Canonicalizado
    utilizando RFC 8785 (JCS).

    El resultado son los bytes exactos que HAEP utilizará
    para las firmas criptográficas.
    """
    return rfc8785.dumps(data)